"""Reader and writer for the `btsnoop` capture format.

btsnoop is what Android ("Enable Bluetooth HCI snoop log") and BlueZ
(`btmon -w out.btsnoop`) produce, and what Wireshark reads.  It is a thin
wrapper around raw HCI packets, which makes it the right primitive to build on:
one file carries the whole link -- advertising, connection setup, SMP pairing,
GATT discovery, and every Attribute Protocol payload afterwards.

File layout
-----------
    header:  b"btsnoop\\x00" | version u32be | datalink u32be          (16 bytes)
    record:  orig_len u32be | incl_len u32be | flags u32be
             | drops u32be | ts_us i64be (since year 0)             (24 bytes)
             | payload[incl_len]

The timestamp is a signed 64-bit count of microseconds since the start of
year 0.  A 32-bit field would wrap every ~71 minutes, which is why it is not
one -- do not "simplify" this to `>IIIII`.

`flags` bit 0 is the direction: 0 = sent (host -> controller),
1 = received (controller -> host).

datalink 1002 ("HCI UART / H4") prefixes each payload with a type octet:
0x01 command, 0x02 ACL, 0x03 SCO, 0x04 event, 0x05 ISO.  datalink 1001
("HCI unencrypted") omits it, so the type has to be inferred -- see
`_infer_hci_type`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone

__all__ = [
    "BtsnoopError",
    "Capture",
    "Record",
    "L2capPdu",
    "write_capture",
    "BTSNOOP_EPOCH_DELTA_US",
    "H4_COMMAND",
    "H4_ACL",
    "H4_EVENT",
    "opcode_name",
    "event_name",
    "att_cid_name",
]

MAGIC = b"btsnoop\x00"
_VERSION = 1

DLT_HCI_UNENCRYPTED = 1001
DLT_HCI_UART = 1002

H4_COMMAND = 0x01
H4_ACL = 0x02
H4_SCO = 0x03
H4_EVENT = 0x04
H4_ISO = 0x05

_H4_NAMES = {
    H4_COMMAND: "command",
    H4_ACL: "acl",
    H4_SCO: "sco",
    H4_EVENT: "event",
    H4_ISO: "iso",
}

# btsnoop timestamps count microseconds from the start of year 0.
# 0x00dcddb30f2f8000 microseconds == 62168256000 seconds to the Unix epoch.
BTSNOOP_EPOCH_DELTA_US = 0x00DCDDB30F2F8000

L2CAP_CID_ATT = 0x0004
L2CAP_CID_SIGNALING = 0x0005
L2CAP_CID_SMP = 0x0006

_L2CAP_CID_NAMES = {
    0x0001: "l2cap-signaling(br/edr)",
    0x0004: "att",
    0x0005: "le-signaling",
    0x0006: "smp",
    0x0007: "smp-br/edr",
}


class BtsnoopError(Exception):
    """Raised when a file is not a usable btsnoop capture."""


def att_cid_name(cid: int) -> str:
    return _L2CAP_CID_NAMES.get(cid, f"cid-0x{cid:04x}")


# --------------------------------------------------------------------------
# HCI symbolic names -- only what shows up in a Mi Band session
# --------------------------------------------------------------------------

_OGF_NAMES = {
    0x01: "Link Control",
    0x02: "Link Policy",
    0x03: "Controller & Baseband",
    0x04: "Informational",
    0x05: "Status",
    0x06: "Testing",
    0x08: "LE Controller",
    0x3F: "Vendor",
}

_LE_OCF_NAMES = {
    0x01: "LE Set Event Mask",
    0x02: "LE Read Buffer Size",
    0x05: "LE Set Random Address",
    0x06: "LE Set Advertising Parameters",
    0x08: "LE Set Advertising Data",
    0x09: "LE Set Scan Response Data",
    0x0A: "LE Set Advertising Enable",
    0x0B: "LE Set Scan Parameters",
    0x0C: "LE Set Scan Enable",
    0x0D: "LE Create Connection",
    0x0E: "LE Create Connection Cancel",
    0x0F: "LE Read White List Size",
    0x10: "LE Clear White List",
    0x11: "LE Add Device To White List",
    0x12: "LE Remove Device From White List",
    0x16: "LE Read Remote Features",
    0x1A: "LE Set Host Channel Classification",
    0x1B: "LE Read Channel Map",
    0x1D: "LE Read Remote Used Features",
    0x1E: "LE Encrypt",
    0x1F: "LE Rand",
    0x20: "LE Enable Encryption",
    0x21: "LE Long Term Key Request Reply",
    0x22: "LE Long Term Key Request Negative Reply",
    0x23: "LE Read Supported States",
    0x25: "LE Read Suggested Default Data Length",
    0x26: "LE Write Suggested Default Data Length",
    0x2C: "LE Read Maximum Data Length",
    0x2D: "LE Read PHY",
    0x2E: "LE Set Default PHY",
    0x2F: "LE Set PHY",
    0x31: "LE Set Extended Advertising Parameters",
    0x37: "LE Set Extended Advertising Enable",
    0x39: "LE Set Extended Scan Parameters",
    0x3A: "LE Set Extended Scan Enable",
    0x3B: "LE Extended Create Connection",
}


def opcode_name(opcode: int) -> str:
    ogf = (opcode >> 10) & 0x3F
    ocf = opcode & 0x3FF
    if ogf == 0x08:
        return _LE_OCF_NAMES.get(ocf, f"LE 0x{ocf:03x}")
    base = _OGF_NAMES.get(ogf, f"OGF 0x{ogf:02x}")
    return f"{base} 0x{ocf:03x}"


_EVENT_NAMES = {
    0x01: "Inquiry Complete",
    0x03: "Connection Complete",
    0x05: "Disconnection Complete",
    0x08: "Encryption Change",
    0x0C: "Read Remote Version Information Complete",
    0x0E: "Command Complete",
    0x0F: "Command Status",
    0x10: "Hardware Error",
    0x13: "Number Of Completed Packets",
    0x17: "Link Supervision Timeout Changed",
    0x1A: "Data Buffer Overflow",
    0x30: "Encryption Key Refresh Complete",
    0x3E: "LE Meta",
}


def event_name(code: int) -> str:
    return _EVENT_NAMES.get(code, f"0x{code:02x}")


_LE_SUBEVENTS = {
    0x01: "LE Connection Complete",
    0x02: "LE Advertising Report",
    0x03: "LE Connection Update Complete",
    0x04: "LE Read Remote Features Complete",
    0x05: "LE Long Term Key Request",
    0x0A: "LE Enhanced Connection Complete",
    0x0C: "LE PHY Update Complete",
    0x12: "LE Data Length Change",
    0x13: "LE Scan Timeout",
    0x14: "LE Advertising Set Terminated",
}


def le_subevent_name(sub: int) -> str:
    return _LE_SUBEVENTS.get(sub, f"LE subevent 0x{sub:02x}")


# --------------------------------------------------------------------------
# Records and packets
# --------------------------------------------------------------------------

@dataclass
class Record:
    """One btsnoop record: a single HCI packet with capture metadata."""

    index: int
    ts_us: int                       # raw btsnoop clock (since year 0)
    flags: int
    orig_len: int
    data: bytes                      # HCI packet, minus any H4 type octet
    hci_type: int | None             # H4_* constant, or None if unidentifiable

    @property
    def from_controller(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def direction(self) -> str:
        return "ctrl->host" if self.from_controller else "host->ctrl"

    @property
    def ts(self) -> float:
        """Capture timestamp as Unix seconds (float)."""
        return (self.ts_us - BTSNOOP_EPOCH_DELTA_US) / 1_000_000.0

    @property
    def ts_iso(self) -> str:
        return datetime.fromtimestamp(self.ts, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"

    @property
    def type_name(self) -> str:
        return _H4_NAMES.get(self.hci_type or -1, "unknown")


@dataclass
class L2capPdu:
    """A complete L2CAP PDU, reassembled across ACL fragments."""

    ts: float
    direction: str
    handle: int
    cid: int
    payload: bytes

    @property
    def channel(self) -> str:
        return att_cid_name(self.cid)


def _infer_hci_type(data: bytes, from_controller: bool) -> int | None:
    """Guess the H4 type octet for datalink 1001 captures.

    There is no type byte in those files.  Both candidate layouts are checked
    against an exact length match; when ambiguous, ACL wins because its handle
    field is far more constrained than a command opcode.
    """
    if len(data) < 2:
        return None

    acl_ok = (
        len(data) >= 4
        and int.from_bytes(data[2:4], "little") + 4 == len(data)
        and 0 < int.from_bytes(data[0:2], "little") & 0x0FFF < 0x0F00
    )

    if from_controller:
        event_ok = data[1] + 2 == len(data)
        if acl_ok and (not event_ok or data[0] < 0x20):
            return H4_ACL
        return H4_EVENT if event_ok else (H4_ACL if acl_ok else None)

    cmd_ok = len(data) >= 3 and data[2] + 3 == len(data)
    if acl_ok and (not cmd_ok or data[0] < 0x20):
        return H4_ACL
    return H4_COMMAND if cmd_ok else (H4_ACL if acl_ok else None)


class Capture:
    """A parsed btsnoop file.

    Iteration order is file order, which for every capture tool of interest is
    chronological.
    """

    def __init__(self, records: list[Record], datalink: int, version: int):
        self.records = records
        self.datalink = datalink
        self.version = version

    # -- construction ------------------------------------------------------

    @classmethod
    def from_bytes(cls, blob: bytes) -> "Capture":
        if len(blob) < 16 or blob[:8] != MAGIC:
            raise BtsnoopError(
                "not a btsnoop file (missing b'btsnoop\\0' magic). "
                "Android bugreport zips store it as btsnoop_hci.log; "
                "Wireshark 'Bluetooth HCI' captures are also readable."
            )
        version, datalink = struct.unpack(">II", blob[8:16])
        records: list[Record] = []
        pos = 16
        idx = 0
        while pos + 24 <= len(blob):
            orig_len, incl_len, flags, _drops, ts_us = struct.unpack(
                ">IIIIq", blob[pos:pos + 24]
            )
            pos += 24
            if incl_len > len(blob) - pos:
                # Truncated tail: a capture that was still being written.
                break
            payload = blob[pos:pos + incl_len]
            pos += incl_len

            from_ctrl = bool(flags & 0x01)
            if datalink == DLT_HCI_UART and payload:
                hci_type = payload[0]
                body = payload[1:]
            elif datalink == DLT_HCI_UNENCRYPTED:
                hci_type = _infer_hci_type(payload, from_ctrl)
                body = payload
            else:
                hci_type = None
                body = payload

            records.append(
                Record(
                    index=idx,
                    ts_us=ts_us,
                    flags=flags,
                    orig_len=orig_len,
                    data=body,
                    hci_type=hci_type,
                )
            )
            idx += 1

        if not records:
            raise BtsnoopError("btsnoop file contains no records")
        return cls(records, datalink, version)

    @classmethod
    def from_file(cls, path: str) -> "Capture":
        with open(path, "rb") as fh:
            return cls.from_bytes(fh.read())

    # -- basic properties --------------------------------------------------

    @property
    def t0(self) -> float:
        return self.records[0].ts

    @property
    def t_end(self) -> float:
        return self.records[-1].ts

    @property
    def span(self) -> float:
        return self.t_end - self.t0

    def rel(self, ts: float) -> float:
        return ts - self.t0

    # -- packet iteration --------------------------------------------------

    def stream(self):
        """Yield `("hci_event", Record)` and `("l2cap", L2capPdu)` in file order.

        Connection setup, pairing and encryption all live in HCI *events*, which
        carry no L2CAP payload at all.  Analysing only ACL traffic therefore
        loses the entire link-setup half of a session -- so events and
        reassembled ACL PDUs are interleaved here rather than separated.

        HCI ACL fragments are keyed by connection handle and chained on the
        packet-boundary flag in bits 12-13 of the handle word:
        0b00/0b10 start a PDU, 0b01 continues one.
        """
        partial: dict[int, bytearray] = {}

        for rec in self.records:
            if rec.hci_type == H4_EVENT:
                yield ("hci_event", rec)
                continue

            if rec.hci_type != H4_ACL or len(rec.data) < 4:
                continue

            word = int.from_bytes(rec.data[0:2], "little")
            handle = word & 0x0FFF
            pb = (word >> 12) & 0x03
            dlen = int.from_bytes(rec.data[2:4], "little")
            frag = rec.data[4:4 + dlen]
            if len(frag) < dlen:
                continue

            if pb in (0x00, 0x02):
                partial[handle] = bytearray(frag)
            elif pb == 0x01:
                buf = partial.get(handle)
                if buf is None:
                    continue
                buf.extend(frag)
            else:
                continue

            buf = partial.get(handle)
            if buf is None or len(buf) < 4:
                continue
            l2_len = int.from_bytes(buf[0:2], "little")
            cid = int.from_bytes(buf[2:4], "little")
            if len(buf) < 4 + l2_len:
                continue          # need more fragments

            payload = bytes(buf[4:4 + l2_len])
            del partial[handle]
            yield (
                "l2cap",
                L2capPdu(
                    ts=rec.ts,
                    direction=rec.direction,
                    handle=handle,
                    cid=cid,
                    payload=payload,
                ),
            )

    def l2cap_pdus(self):
        """Yield only the reassembled L2CAP PDUs, in order."""
        for kind, item in self.stream():
            if kind == "l2cap":
                yield item


# --------------------------------------------------------------------------
# Writing (used by the fixture generator and by hand-authored test vectors)
# --------------------------------------------------------------------------

def _record(ts_unix: float, payload: bytes, from_controller: bool) -> bytes:
    ts_us = int(ts_unix * 1_000_000) + BTSNOOP_EPOCH_DELTA_US
    return struct.pack(
        ">IIIIq",
        len(payload),
        len(payload),
        1 if from_controller else 0,
        0,
        ts_us,
    ) + payload


def write_capture(path: str, packets, datalink: int = DLT_HCI_UART) -> None:
    """Write a capture.

    `packets` is an iterable of `(ts_unix, hci_type, payload, from_controller)`.
    The H4 type octet is written only for datalink 1002.
    """
    out = bytearray(MAGIC + struct.pack(">II", _VERSION, datalink))
    for ts_unix, hci_type, payload, from_ctrl in packets:
        if datalink == DLT_HCI_UART:
            payload = bytes([hci_type]) + payload
        out += _record(ts_unix, payload, from_ctrl)
    with open(path, "wb") as fh:
        fh.write(out)
