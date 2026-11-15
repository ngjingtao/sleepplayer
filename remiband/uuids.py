"""UUID constants and human names for the Mi Band / Xiaomi BLE stack.

Two namespaces matter:

1. Standard Bluetooth SIG UUIDs (`0x180F` battery, `0x2A37` heart rate, ...).
2. The Xiaomi/Mi Band stack, which is *two* services:

   * `0000fee0-...` / `0000fee1-...` -- 16-bit aliases used by the classic
     Mi Band 2/3/4 protocol; characteristics hang off them as `0xff01` ..
     `0xff14`.
   * `0000xxxx-0000-3512-2118-0009af100700` -- the 128-bit Xiaomi base used by
     the auth channel and by the newer (Mi Band 5+/Zepp OS) command channels.
     Note the `3512 2118 0009 af100700` tail: that fixed suffix is what makes a
     Xiaomi UUID recognisable at a glance in a capture.
"""

from __future__ import annotations

__all__ = [
    "MIBAND_SERVICE",
    "MIBAND_AUTH_SERVICE",
    "AUTH_CHARACTERISTIC",
    "STANDARD_SERVICES",
    "STANDARD_CHARACTERISTICS",
    "MIBAND_CHARACTERISTICS",
    "XIAOMI_128_CHARACTERISTICS",
    "uuid128",
    "is_xiaomi",
    "short_uuid",
    "uuid_name",
    "normalize",
]

XIAOMI_TAIL = "0000-3512-2118-0009af100700"

MIBAND_SERVICE = "0000fee0-0000-1000-8000-00805f9b34fb"
MIBAND_AUTH_SERVICE = "0000fee1-0000-1000-8000-00805f9b34fb"

# The auth/secure channel for Mi Band 3 and later.  This is the single most
# important UUID in the whole protocol: everything else is padding until this
# channel has completed its challenge/response.
AUTH_CHARACTERISTIC = "00000009-0000-3512-2118-0009af100700"


def uuid128(value: int) -> str:
    """Build a Xiaomi 128-bit UUID from its 16-bit ordinal."""
    return f"{value:08x}-{XIAOMI_TAIL}"


STANDARD_SERVICES = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute (GATT)",
    "00001802-0000-1000-8000-00805f9b34fb": "Immediate Alert",
    "00001803-0000-1000-8000-00805f9b34fb": "Link Loss",
    "00001804-0000-1000-8000-00805f9b34fb": "Tx Power",
    "00001805-0000-1000-8000-00805f9b34fb": "Current Time Service",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery",
    "00001812-0000-1000-8000-00805f9b34fb": "Human Interface Device",
    "0000181a-0000-1000-8000-00805f9b34fb": "Environmental Sensing",
    "0000181c-0000-1000-8000-00805f9b34fb": "User Data",
    "0000fee0-0000-1000-8000-00805f9b34fb": "Mi Band (main)",
    "0000fee1-0000-1000-8000-00805f9b34fb": "Mi Band (auth)",
    "0000fe95-0000-1000-8000-00805f9b34fb": "Xiaomi MiBeacon (advert)",
    "0000fff0-0000-1000-8000-00805f9b34fb": "Mi Band (vendor fff0)",
    "0000fff1-0000-1000-8000-00805f9b34fb": "Mi Band (vendor fff1)",
    "0000fff2-0000-1000-8000-00805f9b34fb": "Mi Band (vendor fff2)",
}

STANDARD_CHARACTERISTICS = {
    "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
    "00002a01-0000-1000-8000-00805f9b34fb": "Appearance",
    "00002a04-0000-1000-8000-00805f9b34fb": "PPCP",
    "00002a05-0000-1000-8000-00805f9b34fb": "Service Changed",
    "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
    "00002a23-0000-1000-8000-00805f9b34fb": "System ID",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model Number",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Revision",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software Revision",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name",
    "00002a2b-0000-1000-8000-00805f9b34fb": "Current Time",
    "00002a37-0000-1000-8000-00805f9b34fb": "Heart Rate Measurement",
    "00002a38-0000-1000-8000-00805f9b34fb": "Body Sensor Location",
    "00002a39-0000-1000-8000-00805f9b34fb": "Heart Rate Control Point",
    "00002a4a-0000-1000-8000-00805f9b34fb": "HID Information",
    "00002a4d-0000-1000-8000-00805f9b34fb": "Report",
    "00002800-0000-1000-8000-00805f9b34fb": "Primary Service",
    "00002801-0000-1000-8000-00805f9b34fb": "Secondary Service",
    "00002802-0000-1000-8000-00805f9b34fb": "Include",
    "00002803-0000-1000-8000-00805f9b34fb": "Characteristic",
    "00002901-0000-1000-8000-00805f9b34fb": "Characteristic User Description",
    "00002902-0000-1000-8000-00805f9b34fb": "CCCD",
    "00002903-0000-1000-8000-00805f9b34fb": "Server Characteristic Configuration",
    "00002904-0000-1000-8000-00805f9b34fb": "Characteristic Presentation Format",
}

# Classic Mi Band 2/3/4 characteristic surface on service 0xfee0.
# Names are the ones the community converged on; "?" means the purpose is not
# established here and the tool will label it by UUID only.
MIBAND_CHARACTERISTICS = {
    "0000ff01-0000-1000-8000-00805f9b34fb": "device info",
    "0000ff02-0000-1000-8000-00805f9b34fb": "device name",
    "0000ff03-0000-1000-8000-00805f9b34fb": "notification",
    "0000ff04-0000-1000-8000-00805f9b34fb": "user info",
    "0000ff05-0000-1000-8000-00805f9b34fb": "control point",
    "0000ff06-0000-1000-8000-00805f9b34fb": "realtime steps",
    "0000ff07-0000-1000-8000-00805f9b34fb": "activity data",
    "0000ff08-0000-1000-8000-00805f9b34fb": "firmware data",
    "0000ff09-0000-1000-8000-00805f9b34fb": "LE params",
    "0000ff0a-0000-1000-8000-00805f9b34fb": "date/time",
    "0000ff0b-0000-1000-8000-00805f9b34fb": "statistics",
    "0000ff0c-0000-1000-8000-00805f9b34fb": "battery",
    "0000ff0d-0000-1000-8000-00805f9b34fb": "test",
    "0000ff0e-0000-1000-8000-00805f9b34fb": "sensor data",
    "0000ff0f-0000-1000-8000-00805f9b34fb": "pair",
    "0000ff11-0000-1000-8000-00805f9b34fb": "heart rate control",
    "0000ff12-0000-1000-8000-00805f9b34fb": "heart rate data",
    "0000ff13-0000-1000-8000-00805f9b34fb": "auth (legacy)",
    "0000ff14-0000-1000-8000-00805f9b34fb": "alert level",
}

XIAOMI_128_CHARACTERISTICS = {
    uuid128(0x0001): "xiaomi 0x0001",
    uuid128(0x0002): "xiaomi 0x0002 (device info)",
    uuid128(0x0003): "xiaomi 0x0003",
    uuid128(0x0004): "xiaomi 0x0004",
    uuid128(0x0005): "xiaomi 0x0005",
    uuid128(0x0006): "xiaomi 0x0006",
    uuid128(0x0007): "xiaomi 0x0007",
    uuid128(0x0008): "xiaomi 0x0008",
    uuid128(0x0009): "xiaomi 0x0009 (auth)",
    uuid128(0x0010): "xiaomi 0x0010",
    uuid128(0x0012): "xiaomi 0x0012",
    uuid128(0x0014): "xiaomi 0x0014",
    uuid128(0x0015): "xiaomi 0x0015",
    uuid128(0x0016): "xiaomi 0x0016 (chunked/auth)",
    uuid128(0x0017): "xiaomi 0x0017",
    uuid128(0x0019): "xiaomi 0x0019",
    uuid128(0x001a): "xiaomi 0x001a",
    uuid128(0x0020): "xiaomi 0x0020",
    uuid128(0x0021): "xiaomi 0x0021",
    uuid128(0x0022): "xiaomi 0x0022",
    uuid128(0x0023): "xiaomi 0x0023",
    uuid128(0x0024): "xiaomi 0x0024",
}


def normalize(uuid: str | int) -> str:
    """Return a canonical lowercase 128-bit UUID string.

    Accepts an int (16-bit alias or full 32-bit ordinal) or a string in any of
    the shapes that show up in captures: `fee0`, `0xfee0`, `0000fee0`,
    or a full `0000fee0-0000-1000-8000-00805f9b34fb`.
    """
    if isinstance(uuid, int):
        if uuid > 0xFFFF:
            return uuid128(uuid)
        return f"0000{uuid:04x}-0000-1000-8000-00805f9b34fb"
    s = uuid.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) == 4:
        return f"0000{s}-0000-1000-8000-00805f9b34fb"
    if len(s) == 8:
        return f"{s}-0000-1000-8000-00805f9b34fb"
    if "-" not in s and len(s) == 32:
        return f"{s[0:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:32]}"
    return s


def short_uuid(uuid: str) -> str:
    """Compact display form: `fee0`, `2a37`, or `0009af10` for Xiaomi 128-bit."""
    u = normalize(uuid)
    if is_xiaomi(u):
        return f"xiaomi:{u[4:8]}"
    if u.startswith("0000") and u.endswith("-0000-1000-8000-00805f9b34fb"):
        return u[4:8]
    return u[:8]


def is_xiaomi(uuid: str) -> bool:
    return normalize(uuid).endswith(XIAOMI_TAIL)


def uuid_name(uuid: str) -> str | None:
    u = normalize(uuid)
    for table in (
        STANDARD_SERVICES,
        STANDARD_CHARACTERISTICS,
        MIBAND_CHARACTERISTICS,
        XIAOMI_128_CHARACTERISTICS,
    ):
        if u in table:
            return table[u]
    return None
