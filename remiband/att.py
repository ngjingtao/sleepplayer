"""Attribute Protocol (ATT) decoding and GATT database reconstruction.

This is where a capture stops being a byte stream and starts being a device
model.  From the discovery requests alone we can rebuild the peripheral's
entire attribute table -- services, characteristics, descriptors, and which
handle holds what -- without ever connecting to it.  That is the key trick:
**you only need one capture of the official app connecting to identify every
handle in the protocol**, and then you can talk to the device with those
handles forever.

128-bit UUIDs travel little-endian on the wire (least significant byte first),
so they are byte-reversed before being rendered as a canonical UUID string.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import uuids

__all__ = [
    "AttPdu",
    "GattDatabase",
    "Service",
    "Characteristic",
    "decode",
    "ATT_OPCODES",
    "ATT_ERRORS",
    "properties_str",
    "PROP_READ",
    "PROP_WRITE",
    "PROP_WRITE_NO_RSP",
    "PROP_NOTIFY",
    "PROP_INDICATE",
]

ATT_OPCODES = {
    0x01: "ERROR_RSP",
    0x02: "MTU_REQ",
    0x03: "MTU_RSP",
    0x04: "FIND_INFO_REQ",
    0x05: "FIND_INFO_RSP",
    0x06: "FIND_BY_TYPE_VALUE_REQ",
    0x07: "FIND_BY_TYPE_VALUE_RSP",
    0x08: "READ_BY_TYPE_REQ",
    0x09: "READ_BY_TYPE_RSP",
    0x0A: "READ_REQ",
    0x0B: "READ_RSP",
    0x0C: "READ_BLOB_REQ",
    0x0D: "READ_BLOB_RSP",
    0x0E: "READ_MULTI_REQ",
    0x0F: "READ_MULTI_RSP",
    0x10: "READ_BY_GROUP_TYPE_REQ",
    0x11: "READ_BY_GROUP_TYPE_RSP",
    0x12: "WRITE_REQ",
    0x13: "WRITE_RSP",
    0x16: "PREPARE_WRITE_REQ",
    0x17: "PREPARE_WRITE_RSP",
    0x18: "EXEC_WRITE_REQ",
    0x19: "EXEC_WRITE_RSP",
    0x1B: "NOTIFY",
    0x1D: "INDICATE",
    0x1E: "CONFIRM",
    0x52: "WRITE_CMD",
    0xD2: "SIGNED_WRITE_CMD",
}

ATT_ERRORS = {
    0x01: "invalid handle",
    0x02: "read not permitted",
    0x03: "write not permitted",
    0x04: "invalid pdu",
    0x05: "insufficient auth",
    0x06: "request not supported",
    0x07: "invalid offset",
    0x08: "insufficient authorization",
    0x09: "prepare queue full",
    0x0A: "attribute not found",
    0x0B: "attribute not long",
    0x0C: "insufficient encryption key size",
    0x0D: "invalid attribute value length",
    0x0E: "unlikely error",
    0x0F: "insufficient encryption",
    0x11: "insufficient resources",
    0x12: "database out of sync",
    0xFD: "cccd improperly configured",
}

PROP_BROADCAST = 0x01
PROP_READ = 0x02
PROP_WRITE_NO_RSP = 0x04
PROP_WRITE = 0x08
PROP_NOTIFY = 0x10
PROP_INDICATE = 0x20
PROP_AUTH_SIGNED_WRITE = 0x40
PROP_EXTENDED = 0x80

_PROP_FLAGS = (
    (PROP_BROADCAST, "broadcast"),
    (PROP_READ, "read"),
    (PROP_WRITE_NO_RSP, "write-nr"),
    (PROP_WRITE, "write"),
    (PROP_NOTIFY, "notify"),
    (PROP_INDICATE, "indicate"),
    (PROP_AUTH_SIGNED_WRITE, "auth-signed"),
    (PROP_EXTENDED, "extended"),
)


def properties_str(props: int) -> str:
    return ",".join(name for bit, name in _PROP_FLAGS if props & bit) or "-"


def _le16(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off:off + 2], "little")


def uuid_from_wire(buf: bytes) -> str:
    """Render a wire-order UUID (2 or 16 bytes) as a canonical string."""
    if len(buf) == 2:
        return uuids.normalize(_le16(buf, 0))
    if len(buf) == 16:
        return uuids.normalize(buf[::-1].hex())
    return buf.hex()


@dataclass
class AttPdu:
    opcode: int
    name: str
    handle: int | None = None
    value: bytes = b""
    fields: dict = field(default_factory=dict)
    raw: bytes = b""

    @property
    def is_request(self) -> bool:
        return self.opcode in (
            0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10,
            0x12, 0x16, 0x18, 0x52, 0xD2,
        )

    @property
    def is_response(self) -> bool:
        return self.opcode in (
            0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F,
            0x11, 0x13, 0x17, 0x19,
        )

    @property
    def is_notification(self) -> bool:
        return self.opcode in (0x1B, 0x1D)

    def describe(self) -> str:
        if self.opcode in (0x1B, 0x1D, 0x52, 0x12):
            return f"h=0x{self.handle:04x} value={self.value.hex(' ')}"
        if self.opcode == 0x0A:
            return f"read h=0x{self.handle:04x}"
        if self.opcode == 0x08:
            return (
                f"read-by-type 0x{self.fields.get('start', 0):04x}"
                f"..0x{self.fields.get('end', 0):04x}"
                f" type={uuids.short_uuid(self.fields.get('uuid', ''))}"
            )
        if self.opcode == 0x10:
            return (
                f"find-services 0x{self.fields.get('start', 0):04x}"
                f"..0x{self.fields.get('end', 0):04x}"
            )
        if self.opcode == 0x04:
            return (
                f"find-info 0x{self.fields.get('start', 0):04x}"
                f"..0x{self.fields.get('end', 0):04x}"
            )
        if self.opcode == 0x01:
            err = ATT_ERRORS.get(self.fields.get("error", -1), "?")
            return f"error({err}) on h=0x{self.handle or 0:04x}"
        if self.opcode == 0x02:
            return f"mtu req {self.fields.get('mtu')}"
        if self.opcode == 0x03:
            return f"mtu rsp {self.fields.get('mtu')}"
        return f"{self.name} {self.raw.hex(' ')}"


def decode(raw: bytes) -> AttPdu:
    """Decode one ATT PDU.  Never raises on unknown opcodes."""
    if not raw:
        raise ValueError("empty ATT PDU")
    op = raw[0]
    name = ATT_OPCODES.get(op, f"unknown 0x{op:02x}")
    pdu = AttPdu(opcode=op, name=name, raw=raw)

    if op in (0x1B, 0x1D, 0x12, 0x52, 0xD2) and len(raw) >= 3:
        pdu.handle = _le16(raw, 1)
        end = len(raw) - 12 if op == 0xD2 else len(raw)
        pdu.value = raw[3:end]
    elif op == 0x0A and len(raw) >= 3:
        pdu.handle = _le16(raw, 1)
    elif op == 0x0C and len(raw) >= 5:
        pdu.handle = _le16(raw, 1)
        pdu.fields["offset"] = _le16(raw, 3)
    elif op == 0x0B:
        pdu.value = raw[1:]
    elif op == 0x0D:
        pdu.value = raw[1:]
    elif op == 0x13 or op == 0x19 or op == 0x1E:
        pass
    elif op == 0x01 and len(raw) >= 5:
        pdu.fields["req"] = raw[1]
        pdu.handle = _le16(raw, 2)
        pdu.fields["error"] = raw[4]
    elif op == 0x02 and len(raw) >= 3:
        pdu.fields["mtu"] = _le16(raw, 1)
    elif op == 0x03 and len(raw) >= 3:
        pdu.fields["mtu"] = _le16(raw, 1)
    elif op == 0x04 and len(raw) >= 5:
        pdu.fields["start"] = _le16(raw, 1)
        pdu.fields["end"] = _le16(raw, 3)
    elif op == 0x05 and len(raw) >= 2:
        pdu.fields["format"] = raw[1]
    elif op == 0x08 and len(raw) >= 7:
        pdu.fields["start"] = _le16(raw, 1)
        pdu.fields["end"] = _le16(raw, 3)
        pdu.fields["uuid"] = uuid_from_wire(raw[5:])
    elif op == 0x10 and len(raw) >= 7:
        pdu.fields["start"] = _le16(raw, 1)
        pdu.fields["end"] = _le16(raw, 3)
        pdu.fields["uuid"] = uuid_from_wire(raw[5:])
    elif op == 0x09 and len(raw) >= 2:
        pdu.fields["entry_len"] = raw[1]
        pdu.fields["data"] = raw[2:]
    elif op == 0x11 and len(raw) >= 2:
        pdu.fields["entry_len"] = raw[1]
        pdu.fields["data"] = raw[2:]
    elif op == 0x06 and len(raw) >= 7:
        pdu.fields["start"] = _le16(raw, 1)
        pdu.fields["end"] = _le16(raw, 3)
        pdu.fields["uuid"] = uuid_from_wire(raw[5:7])
        pdu.value = raw[7:]
    elif op == 0x0E and len(raw) >= 5:
        pdu.fields["handles"] = [
            _le16(raw, i) for i in range(1, len(raw) - 1, 2)
        ]

    return pdu


@dataclass
class Service:
    start: int
    end: int
    uuid: str
    characteristics: list["Characteristic"] = field(default_factory=list)

    @property
    def name(self) -> str:
        return uuids.uuid_name(self.uuid) or uuids.short_uuid(self.uuid)

    def __str__(self) -> str:
        return (
            f"0x{self.start:04x}-0x{self.end:04x} "
            f"{uuids.short_uuid(self.uuid):<12} {self.name}"
        )


@dataclass
class Characteristic:
    decl_handle: int
    value_handle: int
    uuid: str
    props: int
    service: Service | None = None

    @property
    def name(self) -> str:
        return uuids.uuid_name(self.uuid) or uuids.short_uuid(self.uuid)

    @property
    def can_notify(self) -> bool:
        return bool(self.props & (PROP_NOTIFY | PROP_INDICATE))

    @property
    def can_write(self) -> bool:
        return bool(self.props & (PROP_WRITE | PROP_WRITE_NO_RSP))

    @property
    def can_read(self) -> bool:
        return bool(self.props & PROP_READ)

    def __str__(self) -> str:
        return (
            f"h=0x{self.value_handle:04x} "
            f"{uuids.short_uuid(self.uuid):<12} "
            f"{self.name:<22} [{properties_str(self.props)}]"
        )


class GattDatabase:
    """Attribute table rebuilt from passive observation of discovery."""

    def __init__(self) -> None:
        self.services: list[Service] = []
        self.chars: dict[int, Characteristic] = {}      # by value handle
        self.by_decl: dict[int, Characteristic] = {}    # by declaration handle
        self.attr_uuid: dict[int, str] = {}             # handle -> uuid
        self.values: dict[int, bytes] = {}              # last value per handle
        self.notify_enabled: dict[int, int] = {}        # value handle -> cccd value
        self.mtu_client: int | None = None
        self.mtu_server: int | None = None
        self.errors: list[AttPdu] = []

    # -- incremental construction -----------------------------------------

    def observe(self, req: AttPdu | None, rsp: AttPdu) -> None:
        """Fold one request/response pair into the model."""
        if rsp.opcode == 0x01:
            self.errors.append(rsp)
            return
        if req is not None and req.opcode == 0x02:
            self.mtu_client = req.fields.get("mtu")
        if rsp.opcode == 0x03:
            self.mtu_server = rsp.fields.get("mtu")
            return
        if req is None:
            return

        if rsp.opcode == 0x11:
            self._add_services(rsp)
        elif rsp.opcode == 0x05:
            self._add_find_info(rsp)
        elif rsp.opcode == 0x09 and req.fields.get("uuid", "").startswith("00002803"):
            self._add_characteristics(rsp)
        elif rsp.opcode == 0x0B and req.handle is not None:
            self.values[req.handle] = rsp.value
            self._note_uuid(req.handle)
        elif rsp.opcode == 0x0D and req.handle is not None:
            self.values[req.handle] = (
                self.values.get(req.handle, b"") + rsp.value
            )

    def _note_uuid(self, handle: int) -> None:
        if handle in self.chars:
            self.attr_uuid[handle] = self.chars[handle].uuid

    def _add_services(self, rsp: AttPdu) -> None:
        entry_len = rsp.fields.get("entry_len", 0)
        data = rsp.fields.get("data", b"")
        if entry_len < 6:
            return
        for off in range(0, len(data) - entry_len + 1, entry_len):
            entry = data[off:off + entry_len]
            start = _le16(entry, 0)
            end = _le16(entry, 2)
            u = uuid_from_wire(entry[4:])
            if not any(s.start == start and s.end == end for s in self.services):
                self.services.append(Service(start, end, u))

    def _add_characteristics(self, rsp: AttPdu) -> None:
        entry_len = rsp.fields.get("entry_len", 0)
        data = rsp.fields.get("data", b"")
        if entry_len < 7:
            return
        for off in range(0, len(data) - entry_len + 1, entry_len):
            entry = data[off:off + entry_len]
            decl = _le16(entry, 0)
            props = entry[2]
            value_handle = _le16(entry, 3)
            u = uuid_from_wire(entry[5:])
            service = self._service_for(decl)
            ch = Characteristic(decl, value_handle, u, props, service)
            self.chars[value_handle] = ch
            self.by_decl[decl] = ch
            self.attr_uuid[value_handle] = u
            if service is not None:
                service.characteristics.append(ch)

    def _add_find_info(self, rsp: AttPdu) -> None:
        fmt = rsp.fields.get("format")
        raw = rsp.raw[2:]
        step = 4 if fmt == 0x01 else 18
        if fmt not in (0x01, 0x02):
            return
        for off in range(0, len(raw) - step + 1, step):
            handle = _le16(raw, off)
            u = uuid_from_wire(raw[off + 2:off + step])
            self.attr_uuid[handle] = u
            for ch in self.chars.values():
                if ch.value_handle + 1 == handle and u.endswith("00002902"):
                    self.notify_enabled.setdefault(ch.value_handle, 0)

    def _service_for(self, decl_handle: int) -> Service | None:
        for svc in self.services:
            if svc.start <= decl_handle <= svc.end:
                return svc
        return None

    # -- lookup ------------------------------------------------------------

    def uuid_of(self, handle: int) -> str | None:
        if handle in self.chars:
            return self.chars[handle].uuid
        return self.attr_uuid.get(handle)

    def char_at(self, handle: int) -> Characteristic | None:
        return self.chars.get(handle)

    def label(self, handle: int) -> str:
        ch = self.chars.get(handle)
        if ch is not None:
            return f"{uuids.short_uuid(ch.uuid)} {ch.name}"
        u = self.attr_uuid.get(handle)
        if u is not None:
            return f"{uuids.short_uuid(u)} {uuids.uuid_name(u) or '?'}"
        return f"h=0x{handle:04x} (undiscovered)"

    def cccd_value(self, value_handle: int) -> int | None:
        return self.notify_enabled.get(value_handle)

    def set_cccd(self, value_handle: int, value: int) -> None:
        self.notify_enabled[value_handle] = value

    # -- reporting ---------------------------------------------------------

    def all_characteristics(self) -> list[Characteristic]:
        return sorted(self.chars.values(), key=lambda c: c.value_handle)
