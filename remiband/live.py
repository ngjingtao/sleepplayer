"""Live BLE client for a real Mi Band.

Your hardware, your machine: this module needs a Bluetooth adapter and the
`bleak` package, neither of which exists in the analysis container where the
rest of this toolkit was built and tested.  It is therefore the one file here
that has **not** been executed against a device -- treat it as a starting
point, not a proven client.

Run it where the radio is:

    pip install bleak
    python3 -m remiband live --scan
    python3 -m remiband live --name "Mi Band" --key <32 hex chars>
    python3 -m remiband live --address AA:BB:... --key ... --read 0000ff0c-...

What it does, in order:

1. scan / locate the device
2. connect and dump the full attribute table (resolved against the same
   UUID table the capture decoder uses, so the two views agree)
3. run the AES-128 challenge/response on the auth characteristic
4. optionally read characteristics and send framed commands

Nothing here is required to reverse-engineer the protocol -- a capture is
enough for that.  This exists so you can *test* what the capture suggested.
"""

from __future__ import annotations

import asyncio
import sys
import time

from . import miband, uuids

__all__ = ["main"]


def _require_bleak():
    try:
        from bleak import BleakClient, BleakScanner  # noqa: F401
    except ImportError:
        print(
            "error: `live` needs the bleak package, which is not installed.\n"
            "\n"
            "  pip install bleak\n"
            "\n"
            "Captures from a phone or laptop do not need it: use\n"
            "  python3 -m remiband analyze <capture.btsnoop>\n"
            "instead.",
            file=sys.stderr,
        )
        return None
    import bleak
    return bleak


def _parse_key(text: str | None) -> bytes | None:
    if not text:
        return None
    key = bytes.fromhex(text.replace(":", "").replace(" ", "").replace("-", ""))
    if len(key) != 16:
        raise SystemExit(f"error: key must be 16 bytes, got {len(key)}")
    return key


def main(args) -> int:
    if _require_bleak() is None:
        return 2
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


async def _run(args) -> int:
    from bleak import BleakClient, BleakScanner

    devices = await BleakScanner.discover(timeout=args.timeout)

    if args.scan or not (args.address or args.name):
        if not devices:
            print("no BLE devices found. Is the adapter on?")
            return 1
        print(f"{'address':<20} {'rssi':>5}  name")
        print("-" * 60)
        for d in sorted(devices, key=lambda x: -(x.rssi or -999)):
            name = d.name or ""
            hint = ""
            lowered = name.lower()
            if "mi band" in lowered or "smart band" in lowered or "xiaomi" in lowered:
                hint = "   <- looks like a Mi Band"
            print(f"{d.address:<20} {d.rssi if d.rssi is not None else '?':>5}  "
                  f"{name}{hint}")
        if not (args.address or args.name):
            print("\nPick one with --address or --name.")
            return 0

    target = _select(devices, args)
    if target is None:
        return 1

    print(f"\nconnecting to {target.address} ({target.name or 'unnamed'}) ...")
    disconnected = asyncio.Event()

    def on_disconnect(_client):
        disconnected.set()

    async with BleakClient(
        target.address, timeout=args.timeout, disconnected_callback=on_disconnect
    ) as client:
        print(f"connected. MTU {getattr(client, 'mtu_size', 'unknown')}\n")
        _dump_services(client)

        key = _parse_key(args.key)
        if key is None:
            print("\nNo --key given: the command channel will stay locked.")
        else:
            ok = await _authenticate(client, key)
            if not ok:
                return 1

        for uuid in args.read:
            try:
                data = await client.read_gatt_char(uuid)
            except Exception as exc:  # bleak raises many types
                print(f"read {uuid} failed: {exc}")
                continue
            print(f"read {uuid}: {bytes(data).hex(' ')}")

        for payload in args.send:
            raw = bytes.fromhex(payload.replace(" ", ""))
            target_uuid = args.write_uuid
            print(f"send -> {uuids.short_uuid(target_uuid)}: {raw.hex(' ')}")
            try:
                await client.write_gatt_char(
                    target_uuid, raw, response=not args.no_response
                )
            except Exception as exc:
                print(f"  write failed: {exc}")

        if args.hold > 0:
            print(f"\nholding connection {args.hold:.0f}s (Ctrl-C to stop) ...")
            try:
                await asyncio.wait_for(disconnected.wait(), timeout=args.hold)
            except asyncio.TimeoutError:
                pass

    return 0


def _select(devices, args):
    if args.address:
        for d in devices:
            if d.address.upper() == args.address.upper():
                return d
        print(f"error: {args.address} not in scan results", file=sys.stderr)
        return None
    needle = (args.name or "").lower()
    matches = [d for d in devices if d.name and needle in d.name.lower()]
    if not matches:
        print(f"error: no device name containing {args.name!r}", file=sys.stderr)
        return None
    if len(matches) > 1:
        print(
            "error: several matches, use --address:\n  "
            + "\n  ".join(f"{d.address}  {d.name}" for d in matches),
            file=sys.stderr,
        )
        return None
    return matches[0]


def _dump_services(client) -> None:
    services = list(client.services)
    print(f"ATTRIBUTE TABLE ({len(services)} services)")
    print("-" * 78)
    for svc in sorted(services, key=lambda s: s.handle):
        name = uuids.uuid_name(svc.uuid) or "?"
        print(f"\n  {uuids.short_uuid(svc.uuid):<12} {name}")
        for ch in sorted(svc.characteristics, key=lambda c: c.handle):
            props = ",".join(ch.properties) or "-"
            cname = uuids.uuid_name(ch.uuid) or "?"
            print(
                f"    0x{ch.handle:04x}  {uuids.short_uuid(ch.uuid):<12} "
                f"{cname:<24} [{props}]"
            )


async def _authenticate(client, key: bytes) -> bool:
    """Drive the Mi Band challenge/response.

    Returns True only on an explicit `10 03 01` from the band.  A timeout is
    reported as failure: on this protocol silence is not success.
    """
    auth = miband.AuthSession(key=key)
    queue: asyncio.Queue = asyncio.Queue()

    def on_notify(_sender, data: bytearray) -> None:
        payload = bytes(data)
        auth.feed_notify(payload, time.time())
        queue.put_nowait(payload)

    print(f"\nAUTHENTICATING on {uuids.short_uuid(miband.AUTH_UUID)}")
    print("-" * 78)
    try:
        await client.start_notify(miband.AUTH_UUID, on_notify)
    except Exception as exc:
        print(f"  could not subscribe to the auth characteristic: {exc}")
        print("  This band may use a different auth flow (see docs/protocol.md).")
        return False

    try:
        if auth.state is miband.AuthState.IDLE:
            print(f"  -> {miband.AUTH_START.hex(' ')}   start auth")
            await client.write_gatt_char(
                miband.AUTH_UUID, miband.AUTH_START, response=True
            )
            auth.feed_write(miband.AUTH_START)
            await _await_notification(queue, auth, timeout=5.0)

        for _ in range(12):
            if auth.state in (miband.AuthState.AUTHENTICATED,
                              miband.AuthState.FAILED):
                break
            nxt = auth.next_write()
            if nxt is None:
                break
            print(f"  -> {nxt.hex(' ')}")
            await client.write_gatt_char(miband.AUTH_UUID, nxt, response=True)
            auth.feed_write(nxt)
            await _await_notification(queue, auth, timeout=5.0)
    finally:
        try:
            await client.stop_notify(miband.AUTH_UUID)
        except Exception:
            pass

    if auth.state is miband.AuthState.AUTHENTICATED:
        print("  AUTHENTICATED")
        return True

    print(f"  FAILED (state {auth.state.value})")
    if auth.key_consistent is False:
        print("  your key does not reproduce the band's challenge")
    return False


async def _await_notification(queue: asyncio.Queue, auth, timeout: float) -> None:
    try:
        payload = await asyncio.wait_for(queue.get(), timeout=timeout)
        print(f"  <- {payload.hex(' ')}")
    except asyncio.TimeoutError:
        print(f"  <- (no notification within {timeout:.0f}s)")
