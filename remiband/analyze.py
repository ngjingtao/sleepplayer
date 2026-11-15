"""Walk a btsnoop capture and reconstruct the whole Mi Band session.

The analyzer is passive: it never needs the device, the app, or the key.  It
turns a capture into

  * a chronologically ordered timeline (connect, encryption, MTU, discovery,
    pairing, authentication, commands)
  * the peripheral's attribute table with real UUIDs, recovered from the
    discovery replies
  * a per-handle channel ledger -- who writes what, who notifies what
  * decoded Mi Band envelopes, with multi-chunk commands reassembled
  * the set of command ids that still have no known meaning

Everything in here is derived from bytes in the file.  Anything inferred is
marked as such by `render.py`, never silently asserted.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import att as attmod
from . import btsnoop as bt
from . import miband
from . import uuids

__all__ = [
    "Analysis",
    "ChannelStats",
    "TimelineEvent",
    "DecodedFrame",
    "analyze",
    "format_addr",
]

APP_TO_BAND = "app->band"
BAND_TO_APP = "band->app"


def format_addr(raw: bytes) -> str:
    """Bluetooth addresses arrive little-endian; render most-significant first."""
    return ":".join(f"{b:02X}" for b in reversed(raw))


@dataclass
class TimelineEvent:
    ts: float
    rel: float
    kind: str
    text: str

    def __str__(self) -> str:
        return f"{self.rel:8.3f}s  [{self.kind:<11}] {self.text}"


@dataclass
class ChannelStats:
    handle: int
    uuid: str | None = None
    writes: int = 0
    write_cmds: int = 0
    notifies: int = 0
    indications: int = 0
    reads: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    frames: int = 0
    first_rel: float | None = None
    last_rel: float | None = None

    def touch(self, rel: float) -> None:
        if self.first_rel is None:
            self.first_rel = rel
        self.last_rel = rel

    @property
    def label(self) -> str:
        if self.uuid:
            return f"{uuids.short_uuid(self.uuid)} {uuids.uuid_name(self.uuid) or '?'}"
        return "(undiscovered)"

    @property
    def total(self) -> int:
        return self.writes + self.write_cmds + self.notifies + self.indications


@dataclass
class DecodedFrame:
    rel: float
    direction: str
    handle: int
    label: str
    frame: miband.Frame
    hint: str | None = None
    name: str | None = None
    confidence: str = "unknown"

    def __str__(self) -> str:
        arrow = "->" if self.direction == APP_TO_BAND else "<-"
        bits = [f"{self.rel:8.3f}s {arrow} {self.label:<26}", str(self.frame)]
        if self.name:
            bits.append(f"[{self.name}/{self.confidence}]")
        if self.hint:
            bits.append(f"({self.hint})")
        return "  ".join(bits)


@dataclass
class SmpMessage:
    rel: float
    direction: str
    opcode: int
    name: str
    detail: str


SMP_NAMES = {
    0x01: "Pairing Request",
    0x02: "Pairing Response",
    0x03: "Pairing Confirm",
    0x04: "Pairing Random",
    0x05: "Pairing Failed",
    0x06: "Encryption Information (LTK)",
    0x07: "Master Identification (EDIV/Rand)",
    0x08: "Identity Information (IRK)",
    0x09: "Identity Address Information",
    0x0A: "Signing Information (CSRK)",
    0x0B: "Security Request",
    0x0C: "Public Key",
    0x0D: "DHKey Check",
    0x0E: "Keypress Notification",
}

_SMP_IO_CAPS = {
    0x00: "DisplayOnly",
    0x01: "DisplayYesNo",
    0x02: "KeyboardOnly",
    0x03: "NoInputNoOutput",
    0x04: "KeyboardDisplay",
}


@dataclass
class Analysis:
    path: str
    capture: bt.Capture
    gatt: attmod.GattDatabase = field(default_factory=attmod.GattDatabase)
    auth: miband.AuthSession = field(default_factory=miband.AuthSession)
    events: list[TimelineEvent] = field(default_factory=list)
    channels: dict[int, ChannelStats] = field(default_factory=dict)
    frames: list[DecodedFrame] = field(default_factory=list)
    #: (rel_seconds, handle, direction, value) for every write and notification,
    #: undecoded.  Protocol fingerprinting works on these because it must be
    #: able to say "this is NOT the classic protocol" -- which needs the bytes
    #: the classic decoder would reject.
    samples: list[tuple[float, int, str, bytes]] = field(default_factory=list)
    smp: list[SmpMessage] = field(default_factory=list)
    command_table: miband.CommandTable = field(
        default_factory=miband.CommandTable
    )
    peer_addr: str | None = None
    peer_addr_type: int | None = None
    local_addr: str | None = None
    adv_name: str | None = None
    adv_service_data: list[tuple[str, bytes]] = field(default_factory=list)
    connect_handle: int | None = None
    disconnect_reason: int | None = None
    encryption_enabled: bool | None = None
    mtu: int | None = None
    l2cap_counts: dict[str, int] = field(default_factory=dict)

    # -- convenience -------------------------------------------------------

    def event(self, ts: float, kind: str, text: str) -> None:
        self.events.append(
            TimelineEvent(ts=ts, rel=self.capture.rel(ts), kind=kind, text=text)
        )

    def channel(self, handle: int) -> ChannelStats:
        ch = self.channels.get(handle)
        if ch is None:
            ch = ChannelStats(handle=handle)
            self.channels[handle] = ch
        return ch

    def unresolved_ids(self) -> dict[tuple[str, int], int]:
        """Ids seen in the capture that carry no known meaning.

        Keyed by `(kind, id)`: app->band command ids and band->app response
        ids are separate namespaces, and a name for one says nothing about the
        other, so they must never be merged.
        """
        counts: dict[tuple[str, int], int] = {}
        for df in self.frames:
            f = df.frame
            if f.cmd is None:
                continue
            known, _conf = self.command_table.lookup(f.cmd, f.kind)
            if known is None:
                key = (f.kind.value, f.cmd)
                counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def miband_channels(self) -> list[ChannelStats]:
        return [
            ch for ch in self.channels.values()
            if ch.frames or (ch.uuid and uuids.is_miband(ch.uuid))
        ]

    # -- export ------------------------------------------------------------

    def to_dict(self) -> dict:
        from .fingerprint import fingerprint

        fp = fingerprint(self)
        return {
            "file": self.path,
            "records": len(self.capture.records),
            "datalink": self.capture.datalink,
            "span_seconds": round(self.capture.span, 3),
            "peer_address": self.peer_addr,
            "advertised_name": self.adv_name,
            "mtu": self.mtu,
            "encryption_enabled": self.encryption_enabled,
            "authentication": {
                "authenticated": self.auth.succeeded,
                "state": self.auth.state.value,
                "steps": [
                    {
                        "rel": round(s.at - self.capture.t0, 3) if s.at else None,
                        "direction": s.direction,
                        "detail": s.detail,
                    }
                    for s in self.auth.steps
                ],
            },
            "services": [
                {
                    "range": [s.start, s.end],
                    "uuid": s.uuid,
                    "name": s.name,
                    "characteristics": [
                        {
                            "value_handle": c.value_handle,
                            "decl_handle": c.decl_handle,
                            "uuid": c.uuid,
                            "name": c.name,
                            "properties": attmod.properties_str(c.props),
                        }
                        for c in s.characteristics
                    ],
                }
                for s in self.gatt.services
            ],
            "channels": [
                {
                    "handle": ch.handle,
                    "uuid": ch.uuid,
                    "label": ch.label,
                    "writes": ch.writes,
                    "write_cmds": ch.write_cmds,
                    "notifies": ch.notifies,
                    "reads": ch.reads,
                    "frames": ch.frames,
                    "bytes_out": ch.bytes_out,
                    "bytes_in": ch.bytes_in,
                }
                for ch in sorted(self.channels.values(), key=lambda c: c.handle)
            ],
            "frames": [
                {
                    "rel": round(df.rel, 3),
                    "direction": df.direction,
                    "handle": df.handle,
                    "label": df.label,
                    "kind": df.frame.kind.value,
                    "cmd": df.frame.cmd,
                    "seq": df.frame.seq,
                    "status": df.frame.status,
                    "payload_hex": df.frame.payload.hex(),
                    "hint": df.hint,
                    "name": df.name,
                }
                for df in self.frames
            ],
            "unresolved_ids": [
                {"kind": kind, "id": f"0x{cmd:02x}", "count": count}
                for (kind, cmd), count in self.unresolved_ids().items()
            ],
            "protocol": {
                "verdict": fp.verdict,
                "advice": fp.advice,
                "hypotheses": [
                    {"name": h.name, "score": round(h.score, 3),
                     "evidence": h.evidence}
                    for h in fp.hypotheses
                ],
            },
            "smp": [
                {"rel": round(m.rel, 3), "direction": m.direction,
                 "opcode": m.opcode, "name": m.name, "detail": m.detail}
                for m in self.smp
            ],
            "timeline": [
                {"rel": round(e.rel, 3), "kind": e.kind, "text": e.text}
                for e in self.events
            ],
        }


# --------------------------------------------------------------------------
# HCI event handling
# --------------------------------------------------------------------------

def _le_subevent(params: bytes) -> int | None:
    return params[0] if params else None


def _handle_conn_complete(a: Analysis, ts: float, params: bytes, enhanced: bool) -> None:
    if len(params) < 12:
        return
    status = params[1]
    handle = int.from_bytes(params[2:4], "little")
    role = params[4]
    addr_type = params[5]
    addr = format_addr(params[6:12])

    if status != 0:
        a.event(ts, "error", f"connection failed, HCI status 0x{status:02x}")
        return

    a.connect_handle = handle
    a.peer_addr = addr
    a.peer_addr_type = addr_type
    if enhanced and len(params) >= 24:
        a.local_addr = format_addr(params[13:19])
    role_name = {0: "central", 1: "peripheral", 2: "central", 3: "peripheral"}.get(
        role, f"role{role}"
    )
    a.event(
        ts, "connect",
        f"LE link up  handle=0x{handle:04x}  peer={addr} "
        f"(type {addr_type})  role={role_name}",
    )


def _handle_event(a: Analysis, rec: bt.Record) -> None:
    data = rec.data
    if len(data) < 2:
        return
    code = data[0]
    params = data[2:]

    if code == 0x3E and params:
        sub = _le_subevent(params)
        if sub in (0x01, 0x0A):
            _handle_conn_complete(a, rec.ts, params, enhanced=(sub == 0x0A))
        elif sub == 0x02:
            _handle_adv_report(a, rec.ts, params)
        elif sub == 0x05 and len(params) >= 12:
            handle = int.from_bytes(params[1:3], "little")
            a.event(rec.ts, "bond", f"LE Long Term Key requested (handle 0x{handle:04x})")
        return

    if code == 0x03 and len(params) >= 11:
        _handle_conn_complete(a, rec.ts, params, enhanced=False)

    elif code == 0x05 and len(params) >= 4:
        handle = int.from_bytes(params[1:3], "little")
        reason = params[3]
        a.disconnect_reason = reason
        a.event(rec.ts, "disconnect", f"link down  handle=0x{handle:04x}  reason=0x{reason:02x}")

    elif code == 0x08 and len(params) >= 4:
        status, handle, enabled = params[0], int.from_bytes(params[1:3], "little"), params[3]
        a.encryption_enabled = bool(enabled)
        a.event(
            rec.ts, "encrypt",
            f"link encryption {'ON' if enabled else 'OFF'} "
            f"(handle 0x{handle:04x}, status 0x{status:02x})",
        )


_AD_TYPE_NAMES = {
    0x01: "flags",
    0x02: "uuid16s",
    0x03: "uuid16s-complete",
    0x06: "uuid128s",
    0x07: "uuid128s-complete",
    0x08: "name-short",
    0x09: "name-complete",
    0x0A: "tx-power",
    0x16: "service-data-16",
    0x19: "appearance",
    0xFF: "manufacturer",
}


def _parse_ad(data: bytes) -> list[tuple[int, bytes]]:
    out = []
    i = 0
    while i < len(data):
        ln = data[i]
        if ln == 0 or i + 1 + ln > len(data):
            break
        ad_type = data[i + 1]
        out.append((ad_type, data[i + 2:i + 1 + ln]))
        i += 1 + ln
    return out


def _handle_adv_report(a: Analysis, ts: float, params: bytes) -> None:
    if len(params) < 3:
        return
    off = 2
    while off + 9 <= len(params):
        addr_type = params[off + 1]
        addr = format_addr(params[off + 2:off + 8])
        dlen = params[off + 8]
        ad = params[off + 9:off + 9 + dlen]
        if len(ad) < dlen:
            break
        off += 9 + dlen + 1  # +1 rssi

        for ad_type, body in _parse_ad(ad):
            if ad_type in (0x08, 0x09) and body:
                name = body.decode("utf-8", "replace")
                if name and not a.adv_name:
                    a.adv_name = name
                    a.event(ts, "advert", f"advertising name: {name!r} ({addr})")
            elif ad_type == 0x16 and len(body) >= 2:
                svc = uuids.normalize(int.from_bytes(body[0:2], "little"))
                a.adv_service_data.append((svc, body[2:]))
                a.event(
                    ts, "advert",
                    f"service data {uuids.short_uuid(svc)}: {body[2:].hex(' ')}",
                )
            elif ad_type in (0x02, 0x03):
                for k in range(0, len(body) - 1, 2):
                    u = uuids.normalize(int.from_bytes(body[k:k + 2], "little"))
                    a.event(ts, "advert", f"advertised service {uuids.short_uuid(u)}")


# --------------------------------------------------------------------------
# SMP
# --------------------------------------------------------------------------

def _handle_smp(a: Analysis, pdu: bt.L2capPdu) -> None:
    op = pdu.payload[0]
    name = SMP_NAMES.get(op, f"0x{op:02x}")
    detail = pdu.payload[1:].hex(" ")
    if op in (0x01, 0x02) and len(pdu.payload) >= 7:
        io_cap = pdu.payload[1]
        auth_req = pdu.payload[3]
        detail = (
            f"io={_SMP_IO_CAPS.get(io_cap, hex(io_cap))} "
            f"auth=0x{auth_req:02x} keysize={pdu.payload[4]}"
        )
        if auth_req & 0x08:
            detail += " bonding"
        detail += " (NoInputNoOutput = Just Works, no MITM)"
    elif op == 0x05 and len(pdu.payload) >= 2:
        detail = f"reason 0x{pdu.payload[1]:02x}"
    a.smp.append(
        SmpMessage(
            rel=a.capture.rel(pdu.ts),
            direction=APP_TO_BAND if pdu.direction == "host->ctrl" else BAND_TO_APP,
            opcode=op,
            name=name,
            detail=detail,
        )
    )
    a.event(pdu.ts, "smp", f"{name}  {detail}")


# --------------------------------------------------------------------------
# Main walk
# --------------------------------------------------------------------------

def analyze(path: str, key: bytes | None = None,
            labels: miband.CommandTable | None = None) -> Analysis:
    capture = bt.Capture.from_file(path)
    a = Analysis(path=path, capture=capture)
    if key:
        a.auth.key = key
    if labels is not None:
        a.command_table = labels
    return _walk(a)


def _walk(a: Analysis) -> Analysis:
    cap = a.capture
    pending_req: attmod.AttPdu | None = None
    assembler = miband.ChunkAssembler()
    saw_services = False
    saw_chars = False

    def rel(ts: float) -> float:
        return cap.rel(ts)

    for kind, item in cap.stream():
        if kind == "hci_event":
            _handle_event(a, item)
            continue

        pdu = item
        a.l2cap_counts[pdu.channel] = a.l2cap_counts.get(pdu.channel, 0) + 1

        if pdu.cid == bt.L2CAP_CID_SMP:
            _handle_smp(a, pdu)
            continue

        if pdu.cid != bt.L2CAP_CID_ATT:
            continue

        try:
            p = attmod.decode(pdu.payload)
        except ValueError:
            continue

        if p.opcode == 0x02:                       # MTU exchange request
            pending_req = p
            continue

        if p.opcode == 0x52 or p.opcode == 0x12:   # write cmd / write req
            _handle_write(a, pdu, p, assembler)
            if p.opcode == 0x12:
                pending_req = p
            continue

        if p.opcode in (0x1B, 0x1D):
            _handle_notify(a, pdu, p, assembler)
            continue

        if p.is_request:
            pending_req = p
            continue

        if not p.is_response:
            continue

        # responses: fold into the GATT model
        a.gatt.observe(pending_req, p)
        if pending_req is not None and pending_req.opcode == 0x11 and not saw_services:
            saw_services = True
            n = len(a.gatt.services)
            a.event(pdu.ts, "discover", f"service discovery -> {n} services")
        if pending_req is not None and pending_req.opcode == 0x09 and not saw_chars:
            if a.gatt.chars:
                saw_chars = True
                a.event(
                    pdu.ts, "discover",
                    f"characteristic discovery -> {len(a.gatt.chars)} characteristics",
                )
        if p.opcode == 0x03:
            a.mtu = p.fields.get("mtu")
            a.event(pdu.ts, "mtu", f"ATT MTU = {a.mtu}")
        if p.opcode == 0x01:
            a.event(pdu.ts, "att-error", p.describe())
        pending_req = None

    # anything still buffered
    leftover = assembler.take()
    if leftover is not None:
        _emit_frame(a, cap.t_end, APP_TO_BAND, 0, leftover)

    _finalize(a)
    return a


def _handle_write(a: Analysis, pdu: bt.L2capPdu, p: attmod.AttPdu,
                  assembler: miband.ChunkAssembler) -> None:
    if p.handle is None:
        return
    rel = a.capture.rel(pdu.ts)
    ch = a.channel(p.handle)
    ch.uuid = a.gatt.uuid_of(p.handle) or ch.uuid
    if p.opcode == 0x52:
        ch.write_cmds += 1
    else:
        ch.writes += 1
    ch.bytes_out += len(p.value)
    ch.touch(rel)
    _sample(a, rel, p.handle, APP_TO_BAND, p.value)

    # CCCD writes tell us what the official app subscribes to
    if p.handle - 1 in a.gatt.chars and len(p.value) >= 2:
        target = a.gatt.chars[p.handle - 1]
        if target.can_notify:
            value = int.from_bytes(p.value[0:2], "little")
            a.gatt.set_cccd(target.value_handle, value)
            ch.uuid = uuids.normalize("2902")
            a.event(
                pdu.ts, "subscribe",
                f"{uuids.short_uuid(target.uuid)} {target.name} "
                f"notify={'on' if value & 1 else 'off'}"
                f" indicate={'on' if value & 2 else 'off'}",
            )
            return

    if p.handle == _auth_handle(a) or ch.uuid == miband.AUTH_UUID:
        a.auth.feed_write(p.value, pdu.ts)
        a.event(pdu.ts, "auth", f"write {p.value.hex(' ')}")
        return

    frame = miband.decode_frame(p.value, APP_TO_BAND)
    if frame is None:
        return
    ch.frames += 1
    assembled = assembler.feed(frame)
    if assembled is not None:
        _emit_frame(a, pdu.ts, APP_TO_BAND, p.handle, assembled, assembler_count=True)


def _handle_notify(a: Analysis, pdu: bt.L2capPdu, p: attmod.AttPdu,
                   assembler: miband.ChunkAssembler) -> None:
    if p.handle is None:
        return
    rel = a.capture.rel(pdu.ts)
    ch = a.channel(p.handle)
    ch.uuid = a.gatt.uuid_of(p.handle) or ch.uuid
    if p.opcode == 0x1B:
        ch.notifies += 1
    else:
        ch.indications += 1
    ch.bytes_in += len(p.value)
    ch.touch(rel)
    _sample(a, rel, p.handle, BAND_TO_APP, p.value)

    if ch.uuid == miband.AUTH_UUID:
        a.auth.feed_notify(p.value, pdu.ts)
        a.event(pdu.ts, "auth", f"notify {p.value.hex(' ')}")
        return

    frame = miband.decode_frame(p.value, BAND_TO_APP)
    if frame is None:
        return
    ch.frames += 1
    _emit_frame(a, pdu.ts, BAND_TO_APP, p.handle, frame)


def _sample(a: Analysis, rel: float, handle: int, direction: str,
            value: bytes) -> None:
    # A capture can be large; the fingerprint only needs a representative slice.
    if len(a.samples) < 50000:
        a.samples.append((rel, handle, direction, bytes(value)))


def _auth_handle(a: Analysis) -> int | None:
    for handle, uuid in a.gatt.chars.items():
        if uuid.uuid == miband.AUTH_UUID:
            return handle
    return None


def _emit_frame(a: Analysis, ts: float, direction: str, handle: int,
                frame: miband.Frame, assembler_count: bool = False) -> None:
    ch = a.channel(handle)
    name, conf = a.command_table.lookup(frame.cmd, frame.kind)
    label = a.gatt.label(handle) if handle else "(unattributed)"
    a.frames.append(
        DecodedFrame(
            rel=a.capture.rel(ts),
            direction=direction,
            handle=handle,
            label=label,
            frame=frame,
            hint=miband.payload_hint(frame.payload),
            name=name,
            confidence=conf,
        )
    )


def _finalize(a: Analysis) -> None:
    # Backfill UUIDs now that discovery has completed.
    for handle, ch in a.channels.items():
        if ch.uuid is None:
            ch.uuid = a.gatt.uuid_of(handle)

    if a.auth.succeeded:
        a.event(a.capture.t_end, "auth", "SESSION AUTHENTICATED")
    elif a.auth.state is miband.AuthState.FAILED:
        a.event(a.capture.t_end, "auth", "AUTHENTICATION FAILED")
    elif a.auth.steps:
        a.event(
            a.capture.t_end, "auth",
            f"auth incomplete (ended in state '{a.auth.state.value}'; "
            "command channel would stay locked)",
        )
