"""Build a synthetic but wire-accurate Mi Band session capture.

This exists so the decoder can be tested end to end without a band, a phone, or
a radio: it writes real HCI/L2CAP/ATT bytes through the real btsnoop writer and
the real ATT encoders, then `analyze` has to recover the device model from
those bytes alone.

It is a *fixture*, not a recording.  Numbers were chosen to exercise decoder
paths (16-bit and 128-bit UUIDs, chunked commands, a CCCD write, SMP, the auth
handshake), and it is labelled as synthetic everywhere it is reported.
"""

from __future__ import annotations

import datetime
import os

from . import btsnoop as bt
from . import uuids
from .aes import encrypt_block

__all__ = ["build", "write", "AUTH_KEY", "NONCE", "CT", "T0"]

T0 = datetime.datetime(2026, 11, 12, 14, 0, 0, tzinfo=datetime.timezone.utc).timestamp()

CONN_HANDLE = 0x0040
PEER_ADDR = bytes.fromhex("332211904fc2")     # wire order; renders C2:4F:90:11:22:33

AUTH_KEY = bytes(range(16))
NONCE = bytes.fromhex("00112233445566778899aabbccddeeff")
CT = encrypt_block(AUTH_KEY, NONCE)

# (start, end, uuid16)
SERVICES = [
    (0x0001, 0x0005, 0x1800),
    (0x0006, 0x0009, 0x1801),
    (0x000A, 0x0010, 0x180A),
    (0x0011, 0x0020, 0xFEE0),
    (0x0021, 0x0026, 0xFEE1),
    (0x0027, 0x002A, 0x180F),
]

#: (decl handle, value handle, properties, uuid)
CHARS = [
    (0x0002, 0x0003, 0x02, uuids.normalize(0x2A00)),
    (0x0004, 0x0005, 0x02, uuids.normalize(0x2A01)),
    (0x0007, 0x0008, 0x20, uuids.normalize(0x2A05)),
    (0x000B, 0x000C, 0x02, uuids.normalize(0x2A24)),
    (0x000D, 0x000E, 0x02, uuids.normalize(0x2A26)),
    (0x000F, 0x0010, 0x02, uuids.normalize(0x2A29)),
    (0x0012, 0x0013, 0x02, uuids.normalize(0xFF01)),
    (0x0014, 0x0015, 0x02, uuids.normalize(0xFF02)),
    (0x0016, 0x0017, 0x14, uuids.normalize(0xFF03)),   # write-nr + notify
    (0x0019, 0x001A, 0x04, uuids.normalize(0xFF05)),   # write-nr (control)
    (0x001B, 0x001C, 0x10, uuids.normalize(0xFF06)),   # notify
    (0x001E, 0x001F, 0x12, uuids.normalize(0xFF0C)),   # read + notify
    (0x0022, 0x0023, 0x18, uuids.uuid128(0x0009)),     # write + notify (auth)
    (0x0025, 0x0026, 0x02, uuids.uuid128(0x0001)),
    (0x0028, 0x0029, 0x12, uuids.normalize(0x2A19)),   # battery
]

CCCDS = [0x0009, 0x0018, 0x001D, 0x0020, 0x0024, 0x002A]

H_DEVICE_NAME = 0x0003
H_MODEL = 0x000C
H_FIRMWARE = 0x000E
H_MANUFACTURER = 0x0010
H_BATTERY = 0x001F
H_AUTH = 0x0023
H_CTRL = 0x001A
H_NOTIFY = 0x0017

READS = {
    H_DEVICE_NAME: b"Mi Smart Band 4",
    H_MODEL: b"XMSH07HM",
    H_FIRMWARE: b"1.0.9.30",
    H_MANUFACTURER: b"Xiaomi",
}


def _uuid_wire(uuid: str, size: int) -> bytes:
    if size == 2:
        return int(uuid[4:8], 16).to_bytes(2, "little")
    return bytes.fromhex(uuid.replace("-", ""))[::-1]


def _l2cap(cid: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(2, "little") + cid.to_bytes(2, "little") + payload


def _acl(handle: int, l2cap: bytes, pb: int = 0) -> bytes:
    word = (handle & 0x0FFF) | ((pb & 0x03) << 12)
    return word.to_bytes(2, "little") + len(l2cap).to_bytes(2, "little") + l2cap


def _event(code: int, params: bytes) -> bytes:
    return bytes([code, len(params)]) + params


class _B:
    """Packet accumulator with a monotonically advancing clock."""

    def __init__(self) -> None:
        self.t = T0
        self.pkts: list[tuple[float, int, bytes, bool]] = []

    def tick(self, dt: float) -> float:
        self.t += dt
        return self.t

    def att(self, payload: bytes, from_ctrl: bool, dt: float = 0.004) -> None:
        ts = self.tick(dt)
        self.pkts.append(
            (ts, bt.H4_ACL, _acl(CONN_HANDLE, _l2cap(bt.L2CAP_CID_ATT, payload)),
             from_ctrl)
        )

    def smp(self, payload: bytes, from_ctrl: bool, dt: float = 0.01) -> None:
        ts = self.tick(dt)
        self.pkts.append(
            (ts, bt.H4_ACL, _acl(CONN_HANDLE, _l2cap(bt.L2CAP_CID_SMP, payload)),
             from_ctrl)
        )

    def ev(self, code: int, params: bytes, dt: float = 0.002) -> None:
        ts = self.tick(dt)
        self.pkts.append((ts, bt.H4_EVENT, _event(code, params), True))


def build(text: bytes = b"Hello from MiBand!",
          extra: list[tuple[int, bytes]] | None = None
          ) -> list[tuple[float, int, bytes, bool]]:
    """Build the fixture.

    `text` and `extra` exist so `compare` can be tested against a genuinely
    different session: pass another text to change one payload in place, or
    extra (command id, payload) pairs to add traffic that the baseline lacks.
    """
    b = _B()

    # -- advertising ------------------------------------------------------
    name = b"Mi Smart Band 4"
    ad = bytes([len(name) + 1, 0x09]) + name
    svc = bytes([0x95, 0xFE, 0x01, 0x00, 0x00, 0x00])
    ad += bytes([len(svc), 0x16]) + svc
    params = bytes([0x02, 0x01, 0x00, 0x00]) + PEER_ADDR + bytes([len(ad)]) + ad + b"\xc4"
    b.ev(0x3E, params)

    # -- connection -------------------------------------------------------
    conn = (
        bytes([0x01, 0x00])                  # subevent, status
        + CONN_HANDLE.to_bytes(2, "little")
        + bytes([0x01, 0x00])                # role=peripheral, addr_type=public
        + PEER_ADDR
        + (24).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
        + (72).to_bytes(2, "little")
        + bytes([0x01])
    )
    b.ev(0x3E, conn, dt=0.10)

    # -- MTU --------------------------------------------------------------
    b.att(bytes([0x02]) + (185).to_bytes(2, "little"), from_ctrl=False)
    b.att(bytes([0x03]) + (185).to_bytes(2, "little"), from_ctrl=True)

    # -- service discovery ------------------------------------------------
    b.att(bytes([0x10]) + (0x0001).to_bytes(2, "little")
          + (0xFFFF).to_bytes(2, "little") + (0x2800).to_bytes(2, "little"),
          from_ctrl=False)
    entries = b"".join(
        start.to_bytes(2, "little") + end.to_bytes(2, "little")
        + _uuid_wire(uuids.normalize(u), 2)
        for start, end, u in SERVICES
    )
    b.att(bytes([0x11, 6]) + entries, from_ctrl=True)

    # -- characteristic discovery, one service range at a time ------------
    for start, end, svc_uuid in SERVICES:
        chars = [c for c in CHARS if start <= c[0] <= end]
        if not chars:
            continue
        size = 16 if uuids.normalize(svc_uuid) == uuids.MIBAND_AUTH_SERVICE else 2
        b.att(bytes([0x08]) + start.to_bytes(2, "little")
              + end.to_bytes(2, "little") + (0x2803).to_bytes(2, "little"),
              from_ctrl=False)
        entry_len = 5 + size
        blob = b""
        for decl, value, props, uuid in chars:
            blob += (
                decl.to_bytes(2, "little")
                + bytes([props])
                + value.to_bytes(2, "little")
                + _uuid_wire(uuid, size)
            )
        b.att(bytes([0x09, entry_len]) + blob, from_ctrl=True)

    # -- descriptor discovery ---------------------------------------------
    for h in CCCDS:
        b.att(bytes([0x04]) + h.to_bytes(2, "little") + h.to_bytes(2, "little"),
              from_ctrl=False)
        b.att(bytes([0x05, 0x01]) + h.to_bytes(2, "little")
              + (0x2902).to_bytes(2, "little"), from_ctrl=True)

    # -- reads ------------------------------------------------------------
    for handle, value in READS.items():
        b.att(bytes([0x0A]) + handle.to_bytes(2, "little"), from_ctrl=False)
        b.att(bytes([0x0B]) + value, from_ctrl=True)

    b.att(bytes([0x0A]) + H_BATTERY.to_bytes(2, "little"), from_ctrl=False)
    b.att(bytes([0x0B, 0x5A]), from_ctrl=True)

    # -- subscribe --------------------------------------------------------
    for h in (0x0018, 0x001D, 0x0024):
        b.att(bytes([0x52]) + h.to_bytes(2, "little") + b"\x01\x00",
              from_ctrl=False)

    # -- SMP: Just Works, bonding ----------------------------------------
    b.smp(bytes([0x01, 0x03, 0x00, 0x09, 0x10, 0x0F, 0x0F]), from_ctrl=False)
    b.smp(bytes([0x02, 0x03, 0x00, 0x09, 0x10, 0x0F, 0x0F]), from_ctrl=True)
    b.smp(bytes([0x03]) + b"\x11" * 16, from_ctrl=False)
    b.smp(bytes([0x03]) + b"\x22" * 16, from_ctrl=True)
    b.smp(bytes([0x04]) + b"\x33" * 16, from_ctrl=False)
    b.smp(bytes([0x04]) + b"\x44" * 16, from_ctrl=True)
    b.smp(bytes([0x06]) + b"\xAA" * 16, from_ctrl=True)
    b.smp(bytes([0x07, 0x00, 0x00]) + b"\xBB" * 8, from_ctrl=True)

    b.ev(0x08, bytes([0x00]) + CONN_HANDLE.to_bytes(2, "little") + bytes([0x01]),
         dt=0.05)

    # -- Mi Band authentication ------------------------------------------
    def auth_write(value: bytes, dt: float = 0.02) -> None:
        b.att(bytes([0x12]) + H_AUTH.to_bytes(2, "little") + value,
              from_ctrl=False, dt=dt)
        b.att(bytes([0x13]), from_ctrl=True, dt=0.004)

    def auth_notify(value: bytes, dt: float = 0.02) -> None:
        b.att(bytes([0x1B]) + H_AUTH.to_bytes(2, "little") + value,
              from_ctrl=True, dt=dt)

    auth_notify(b"\x10\x01\x01")
    auth_write(bytes([0x01, 0x08]))
    auth_write(bytes([0x02, 0x00]))
    auth_notify(b"\x10\x02\x01" + NONCE)
    auth_write(bytes([0x03, 0x00]) + CT)
    auth_notify(b"\x10\x03\x01")

    # -- command channel --------------------------------------------------
    def cmd(value: bytes, dt: float = 0.03) -> None:
        b.att(bytes([0x52]) + H_CTRL.to_bytes(2, "little") + value,
              from_ctrl=False, dt=dt)

    def notify(value: bytes, dt: float = 0.02) -> None:
        b.att(bytes([0x1B]) + H_NOTIFY.to_bytes(2, "little") + value,
              from_ctrl=True, dt=dt)

    # set date/time: 2026-11-12 14:00:00
    cmd(bytes([0xA0, 0x02, 0x00, 0x06, 0xEA, 0x07, 0x0B, 0x0C, 0x0E, 0x00]))
    notify(bytes([0xA0, 0x01, 0x02, 0x01]))

    # device info request
    cmd(bytes([0xA0, 0x01, 0x00, 0x01, 0x00]))
    notify(bytes([0xA0, 0x01, 0x01, 0x01, 0x00]))

    # a command that fails
    cmd(bytes([0xA0, 0x13, 0x00, 0x02, 0x01, 0x02]))
    notify(bytes([0xA0, 0x01, 0x13, 0x00]))

    # chunked text notification, 16 bytes per chunk
    assert len(text) > 0
    for seq, off in enumerate(range(0, len(text), 16)):
        piece = text[off:off + 16]
        cmd(bytes([0xA0, 0x0A, seq & 0xFF, len(piece)]) + piece)

    # battery notification
    notify(bytes([0xA0, 0x01, 0x0C, 0x01, 0x5A]))

    # anything the caller wants appended (used by the diff tests)
    for cmd_id, payload in (extra or []):
        for seq, off in enumerate(range(0, len(payload), 16)):
            piece = payload[off:off + 16]
            cmd(bytes([0xA0, cmd_id, seq & 0xFF, len(piece)]) + piece)
        notify(bytes([0xA0, 0x01, cmd_id, 0x01]))

    return b.pkts


def build_zepp_like() -> list[tuple[float, int, bytes, bool]]:
    """A capture shaped like a newer (Zepp OS lineage) band: NO 0xA0 framing.

    Fixed-size opaque blocks with a running counter, on 128-bit characteristics
    under service 0xfee0.  This exists to prove the fingerprint can say "this is
    not the classic protocol" instead of silently finding zero frames.
    """
    b = _B()

    name = b"Xiaomi Smart Band 10"
    ad = bytes([len(name) + 1, 0x09]) + name
    params = bytes([0x02, 0x01, 0x00, 0x00]) + PEER_ADDR + bytes([len(ad)]) + ad + b"\xc0"
    b.ev(0x3E, params)

    conn = (
        bytes([0x01, 0x00])
        + CONN_HANDLE.to_bytes(2, "little")
        + bytes([0x01, 0x00])
        + PEER_ADDR
        + (24).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
        + (72).to_bytes(2, "little")
        + bytes([0x01])
    )
    b.ev(0x3E, conn, dt=0.10)

    b.att(bytes([0x02]) + (247).to_bytes(2, "little"), from_ctrl=False)
    b.att(bytes([0x03]) + (247).to_bytes(2, "little"), from_ctrl=True)

    # one service, 128-bit characteristics
    b.att(bytes([0x10]) + (0x0001).to_bytes(2, "little")
          + (0xFFFF).to_bytes(2, "little") + (0x2800).to_bytes(2, "little"),
          from_ctrl=False)
    b.att(bytes([0x11, 6])
          + (0x0011).to_bytes(2, "little") + (0x0015).to_bytes(2, "little")
          + _uuid_wire(uuids.normalize(0xFEE0), 2), from_ctrl=True)

    b.att(bytes([0x08]) + (0x0011).to_bytes(2, "little")
          + (0x0015).to_bytes(2, "little") + (0x2803).to_bytes(2, "little"),
          from_ctrl=False)
    blob = b""
    for decl, value, props, uuid in (
        (0x0012, 0x0013, 0x1C, uuids.uuid128(0x0016)),
        (0x0014, 0x0015, 0x1C, uuids.uuid128(0x0017)),
    ):
        blob += (decl.to_bytes(2, "little") + bytes([props])
                 + value.to_bytes(2, "little") + _uuid_wire(uuid, 16))
    b.att(bytes([0x09, 21]) + blob, from_ctrl=True)

    # opaque 20-byte blocks, counter in byte 0
    def block(seq: int) -> bytes:
        body = bytes(((k * 53 + seq * 29 + 11) & 0xFF) for k in range(1, 20))
        return bytes([seq & 0xFF]) + body

    for seq in range(12):
        b.att(bytes([0x52]) + (0x0013).to_bytes(2, "little") + block(seq),
              from_ctrl=False, dt=0.03)
    for seq in range(12, 18):
        b.att(bytes([0x1B]) + (0x0013).to_bytes(2, "little") + block(seq),
              from_ctrl=True, dt=0.04)

    return b.pkts


def write(path: str, style: str = "classic", **kwargs) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    packets = build_zepp_like() if style == "zepp" else build(**kwargs)
    bt.write_capture(path, packets)
    return path


if __name__ == "__main__":  # pragma: no cover
    import sys
    print(write(sys.argv[1] if len(sys.argv) > 1 else "fixtures/miband_demo.btsnoop"))
