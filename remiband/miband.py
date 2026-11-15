"""Mi Band application-layer framing and the authentication handshake.

Two layers live here.

Framing
-------
Above ATT, the classic Mi Band protocol (Mi Band 2/3/4 and relatives) wraps
every message in a fixed envelope starting with 0xA0:

    to band    a0 <cmd> <seq> <len> <payload...>
    from band  a0 01 <type> <status> <payload...>

`seq` makes long commands sendable over a 20-byte ATT MTU: seq 0 starts a
message, 1, 2, ... continue it, and `len` is the byte count in *that* chunk.
`status` 0x01 reads as success, 0x00 as failure -- this is the convention in
the community documentation and is worth confirming against your own capture
before trusting it.

The decoder therefore treats the first four bytes as *structure* and never
depends on knowing what a given command id means.  Semantic labels live in a
separate, editable table (see `CommandTable`) so this file stays honest: it
decodes shapes it is sure about and refuses to invent meanings.

Authentication
--------------
Mi Band 3 and later gate the command channel behind an AES-128 challenge on
`00000009-0000-3512-2118-0009af100700` (service `0000fee1`):

    app -> band   01 08                       start auth
    band -> app   10 01 01                    ready, send the nonce request
    app -> band   02 00                       request random nonce
    band -> app   10 02 01 <16-byte nonce>     challenge
    app -> band   03 00 <AES-ECB(key, nonce)>  response
    band -> app   10 03 01                    authenticated

The 16-byte key is per-device and is provisioned by the Xiaomi cloud during
pairing, not derived from anything on the band.  Without it you can still read
the whole GATT table and every unauthenticated characteristic; you cannot
issue commands.  See docs/protocol.md for how to obtain yours legitimately.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum

from .aes import encrypt_block

__all__ = [
    "FRAME_MARKER",
    "Frame",
    "FrameKind",
    "decode_frame",
    "ChunkAssembler",
    "AuthState",
    "AuthSession",
    "CommandTable",
    "payload_hint",
    "AUTH_UUID",
    "AUTH_START",
    "AUTH_NONCE_REQ",
    "AUTH_RESPONSE_PREFIX",
]

FRAME_MARKER = 0xA0

# Authentication channel (service 0000fee1, characteristic 00000009-...)
AUTH_UUID = "00000009-0000-3512-2118-0009af100700"
AUTH_START = bytes([0x01, 0x08])
AUTH_NONCE_REQ = bytes([0x02, 0x00])
AUTH_RESPONSE_PREFIX = bytes([0x03, 0x00])

AUTH_NOTIFY_PREFIX = 0x10


class FrameKind(str, Enum):
    COMMAND = "command"      # app -> band
    RESPONSE = "response"    # band -> app, 0xa0 0x01 ...
    RAW = "raw"              # 0xa0 but shaped unexpectedly


@dataclass
class Frame:
    kind: FrameKind
    raw: bytes
    cmd: int | None = None          # app->band command id, or band->app type
    seq: int = 0
    declared_len: int | None = None
    status: int | None = None       # band->app result byte
    payload: bytes = b""

    @property
    def ok(self) -> bool | None:
        if self.status is None:
            return None
        return self.status == 0x01

    @property
    def continued(self) -> bool:
        return self.kind is FrameKind.COMMAND and self.seq > 0

    def header(self) -> str:
        if self.kind is FrameKind.COMMAND:
            return f"cmd=0x{self.cmd:02x} seq={self.seq} len={self.declared_len}"
        if self.kind is FrameKind.RESPONSE:
            return (
                f"type=0x{self.cmd:02x} status=0x{self.status:02x}"
                f" ({'ok' if self.ok else 'fail'})"
            )
        return "unframed"

    def __str__(self) -> str:
        body = f"{self.header()} | {self.payload.hex(' ')}" if self.payload else self.header()
        return f"{self.kind.value}: {body}"


def decode_frame(data: bytes, direction: str) -> Frame | None:
    """Decode one Mi Band envelope.

    `direction` is `"app->band"` (an ATT write) or `"band->app"` (a
    notification).  Returns None when the payload is not Mi Band framed --
    that is normal, the band also carries ordinary GATT attributes.
    """
    if not data or data[0] != FRAME_MARKER:
        return None

    if direction == "band->app":
        if len(data) < 2:
            return Frame(FrameKind.RAW, data)
        # a0 01 <type> <status> <payload>
        if len(data) >= 4 and data[1] == 0x01:
            return Frame(
                kind=FrameKind.RESPONSE,
                raw=data,
                cmd=data[2],
                status=data[3],
                declared_len=len(data) - 4,
                payload=data[4:],
            )
        return Frame(kind=FrameKind.RAW, raw=data, payload=data[1:])

    # app -> band
    if len(data) < 3:
        return Frame(FrameKind.RAW, data)
    seq = data[2]
    declared = data[3] if len(data) >= 4 else 0
    payload = data[4:4 + declared] if declared else data[4:]
    if len(payload) < declared:
        payload = data[4:]
    return Frame(
        kind=FrameKind.COMMAND,
        raw=data,
        cmd=data[1],
        seq=seq,
        declared_len=declared,
        payload=payload,
    )


#: Payload capacity of one chunk: 20-byte ATT write value minus the 4-byte
#: Mi Band header.  A chunk shorter than this is therefore the last one.
CHUNK_PAYLOAD = 16


class ChunkAssembler:
    """Reassemble multi-chunk commands (seq 0, 1, 2, ...) per direction.

    A 20-byte ATT MTU leaves 16 payload bytes per chunk, so any command with a
    longer payload -- a notification text, a workout record -- arrives split.
    The rule used here needs only one fact: a full 16-byte chunk means "more
    follows", a short chunk means "this ends the message".  The trailing seq
    byte corroborates it but is not required, which matters because some
    firmware repeats seq 0 for every chunk.
    """

    def __init__(self) -> None:
        self._pending: tuple[int, bytearray, list[bytes]] | None = None

    def feed(self, frame: Frame) -> Frame | None:
        """Return the completed frame, or None while still collecting."""
        if frame.kind is not FrameKind.COMMAND:
            return frame

        if frame.seq == 0:
            if len(frame.payload) < CHUNK_PAYLOAD:
                # A short first chunk can only be a complete message.
                self._pending = None
                return frame
            self._pending = (frame.cmd, bytearray(frame.payload), [frame.raw])
            return None

        if self._pending is None:
            # Continuation with no start (capture began mid-transfer, or the
            # firmware restarted seq): treat it as a message of its own.
            self._pending = (frame.cmd, bytearray(frame.payload), [frame.raw])
        else:
            cmd, buf, raws = self._pending
            buf.extend(frame.payload)
            raws.append(frame.raw)
            self._pending = (cmd, buf, raws)

        cmd, buf, raws = self._pending
        if len(frame.payload) >= CHUNK_PAYLOAD:
            return None

        self._pending = None
        return Frame(
            kind=FrameKind.COMMAND,
            raw=b"".join(raws),
            cmd=cmd,
            seq=frame.seq,
            declared_len=len(buf),
            payload=bytes(buf),
        )

    def take(self) -> Frame | None:
        """Flush an unterminated message (capture ended mid-transfer)."""
        if self._pending is None:
            return None
        cmd, buf, raws = self._pending
        self._pending = None
        return Frame(
            kind=FrameKind.COMMAND,
            raw=b"".join(raws),
            cmd=cmd,
            seq=0,
            declared_len=len(buf),
            payload=bytes(buf),
        )


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

class AuthState(str, Enum):
    IDLE = "idle"
    START_SENT = "start-sent"
    READY = "ready"
    NONCE_REQUESTED = "nonce-requested"
    CHALLENGE_SENT = "challenge-sent"
    AUTHENTICATED = "authenticated"
    FAILED = "failed"


@dataclass
class AuthStep:
    at: float | None
    direction: str
    detail: str
    state: AuthState


@dataclass
class AuthSession:
    """Tracks (and can drive) the Mi Band auth exchange.

    Fed passively, it narrates a capture.  Fed actively by `live.py`, it
    produces the exact bytes to write next.
    """

    key: bytes | None = None
    state: AuthState = AuthState.IDLE
    nonce: bytes | None = None
    response: bytes | None = None
    #: Whether the key we hold actually reproduces the capture's response.
    #: `None` means unknown (no key supplied, or no challenge seen).
    #: Distinct from `state`: the capture can narrate "authenticated" while our
    #: key is nonetheless demonstrably wrong, and that difference matters.
    key_consistent: bool | None = None
    steps: list[AuthStep] = field(default_factory=list)
    pending_write: bytes | None = None

    # -- helpers -----------------------------------------------------------

    def _log(self, at: float | None, direction: str, detail: str) -> None:
        self.steps.append(AuthStep(at, direction, detail, self.state))

    def compute_response(self) -> bytes | None:
        if self.key is None or self.nonce is None:
            return None
        if len(self.key) != 16 or len(self.nonce) != 16:
            return None
        return encrypt_block(self.key, self.nonce)

    # -- passive narration -------------------------------------------------

    def feed_write(self, value: bytes, at: float | None = None) -> None:
        """Feed an app->band write on the auth characteristic."""
        if value == AUTH_START:
            self.state = AuthState.START_SENT
            self._log(at, "app->band", "start auth (01 08)")
        elif value == AUTH_NONCE_REQ:
            self.state = AuthState.NONCE_REQUESTED
            self._log(at, "app->band", "request nonce (02 00)")
        elif value[:2] == AUTH_RESPONSE_PREFIX and len(value) == 18:
            self.challenge = value[2:]
            self.state = AuthState.CHALLENGE_SENT
            self._log(
                at, "app->band",
                f"challenge response ({value[2:].hex()})",
            )
            self._check_key_match(value[2:])
        else:
            self._log(at, "app->band", f"other write ({value.hex(' ')})")

    def _check_key_match(self, sent: bytes) -> None:
        """If we hold the key, say whether the capture's response proves it."""
        expected = self.compute_response()
        if expected is None:
            return
        if expected == sent:
            self.key_consistent = True
            self._log(None, "analysis", "AES-128-ECB(key, nonce) MATCHES capture")
        else:
            self.key_consistent = False
            self._log(
                None, "analysis",
                "AES-128-ECB(key, nonce) does NOT match capture "
                f"(expected {expected.hex()}) -- wrong key, or a different "
                "KDF/transform on this firmware",
            )

    def feed_notify(self, value: bytes, at: float | None = None) -> None:
        """Feed a band->app notification on the auth characteristic."""
        if not value or value[0] != AUTH_NOTIFY_PREFIX:
            self._log(at, "band->app", f"unknown notify ({value.hex(' ')})")
            return

        sub = value[1] if len(value) > 1 else None
        code = value[2] if len(value) > 2 else None

        if sub == 0x01:
            if code == 0x01:
                self.state = AuthState.READY
                self._log(at, "band->app", "auth ready (10 01 01)")
            else:
                self._log(at, "band->app", f"auth 10 01 0x{code:02x}")
        elif sub == 0x02:
            if code == 0x01 and len(value) >= 19:
                self.nonce = value[3:19]
                self.response = self.compute_response()
                self.state = AuthState.NONCE_REQUESTED
                self._log(
                    at, "band->app",
                    f"nonce (10 02 01 {self.nonce.hex()})",
                )
                if self.response is not None:
                    self._log(
                        None, "analysis",
                        f"expected app response = 03 00 {self.response.hex()}",
                    )
            else:
                self._log(at, "band->app", f"nonce rejected ({value.hex(' ')})")
        elif sub == 0x03:
            if code == 0x01:
                self.state = AuthState.AUTHENTICATED
                self._log(at, "band->app", "AUTHENTICATED (10 03 01)")
            else:
                self.state = AuthState.FAILED
                self._log(
                    at, "band->app",
                    f"AUTH FAILED (10 03 0x{code:02x}) -- wrong 16-byte key",
                )
        else:
            self._log(at, "band->app", f"notify ({value.hex(' ')})")

    # -- active driving ----------------------------------------------------

    def next_write(self) -> bytes | None:
        """Scan-driven: the next byte string the app should send."""
        if self.state in (AuthState.IDLE,):
            return AUTH_START
        if self.state is AuthState.READY:
            return AUTH_NONCE_REQ
        if self.state is AuthState.NONCE_REQUESTED and self.response is not None:
            return AUTH_RESPONSE_PREFIX + self.response
        return None

    @property
    def succeeded(self) -> bool:
        return self.state is AuthState.AUTHENTICATED


# --------------------------------------------------------------------------
# Semantic labels -- deliberately a separate, editable table
# --------------------------------------------------------------------------

#: Seed entries.  Every one is *structural* or widely reported; none of them is
#: needed to decode a capture, and the analyzer always prints the numeric id
#: next to the label so a wrong label is visible rather than hidden.
SEED_COMMANDS: dict[int, tuple[str, str]] = {
    0x0E: ("auth", "medium"),
    0x01: ("device info / hello", "low"),
    0x02: ("set date-time", "low"),
}

#: Notifications the band pushes unsolicited, same id space as responses.
SEED_RESPONSES: dict[int, tuple[str, str]] = {
    0x01: ("ack", "low"),
    0x0E: ("auth result", "medium"),
}


class CommandTable:
    """Editable command id -> meaning map, persisted as JSON.

    Kept separate from the decoder on purpose: guessing meanings is the part
    that must be evidence-driven, and the JSON makes every guess reviewable and
    cheap to correct as the capture proves it wrong.
    """

    def __init__(self, path: str | None = None) -> None:
        self.path = path
        self.commands: dict[int, tuple[str, str]] = dict(SEED_COMMANDS)
        self.responses: dict[int, tuple[str, str]] = dict(SEED_RESPONSES)
        if path and os.path.exists(path):
            self.load(path)

    def load(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as fh:
            blob = json.load(fh)
        for section, target in (
            ("commands", self.commands),
            ("responses", self.responses),
        ):
            for k, v in (blob.get(section) or {}).items():
                key = int(k, 0) if isinstance(k, str) else int(k)
                if isinstance(v, str):
                    target[key] = (v, "user")
                else:
                    target[key] = (v[0], v[1] if len(v) > 1 else "user")

    def save(self, path: str | None = None) -> None:
        out = {
            "commands": {f"0x{k:02x}": list(v) for k, v in sorted(self.commands.items())},
            "responses": {f"0x{k:02x}": list(v) for k, v in sorted(self.responses.items())},
        }
        with open(path or self.path or "labels.json", "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2, ensure_ascii=False)

    def lookup(self, cmd: int | None, kind: FrameKind) -> tuple[str | None, str]:
        if cmd is None:
            return None, "unknown"
        table = self.commands if kind is FrameKind.COMMAND else self.responses
        hit = table.get(cmd)
        return hit if hit else (None, "unknown")


# --------------------------------------------------------------------------
# Content heuristics -- evidence, not labels
# --------------------------------------------------------------------------

def payload_hint(payload: bytes) -> str | None:
    """Describe what a payload *looks like* without claiming what it means.

    These hints come from the bytes themselves and are testable; they are how
    you bootstrap a command table from a capture without guessing.
    """
    if not payload:
        return None

    if len(payload) >= 2:
        year = int.from_bytes(payload[0:2], "little")
        if 1980 <= year <= 2200:
            rest = payload[2:]
            if 5 <= len(rest) <= 8:
                parts = [year] + [
                    rest[i] if i < len(rest) else 0 for i in range(len(rest))
                ]
                return f"timestamp-like: {'-'.join(str(p) for p in parts[:6])}"

    if len(payload) >= 4:
        if all(32 <= b < 127 or b == 0x00 for b in payload) and any(
            32 <= b < 127 for b in payload
        ):
            text = payload.split(b"\x00")[0].decode("ascii", "replace")
            if text.strip():
                return f"text-like: {text!r}"

    if len(payload) <= 2:
        return f"scalar-like: {int.from_bytes(payload, 'little')}"
    return None
