# Getting a capture

Everything else in this toolkit works offline. This is the one step that needs
the band.

Pick the source by what you want to learn:

| Source | Best for | Shows | Setup |
|---|---|---|---|
| **Android HCI snoop log** | the app's own behaviour, commands | every ATT byte in plaintext | developer option, no hardware |
| **`btmon` on Linux** | talking to the band from a laptop | every ATT byte in plaintext | one command, needs the adapter |
| **nRF sniffer + Wireshark** | pairing, timing, over-the-air detail | raw air packets, encrypted after bonding | nRF52840 dongle |

An HCI log is taken *above* the controller, so the host sees decrypted
attribute traffic even though the air interface is encrypted. For protocol
work that is exactly what you want: no key needed to read the bytes.

---

## Android: HCI snoop log

1. Settings → About phone → tap *Build number* seven times.
2. Developer options → **Enable Bluetooth HCI snoop log**.
3. Toggle Bluetooth **off and on** (the setting only takes effect on a fresh
   stack start).
4. Reproduce the behaviour (see the checklist below).
5. Pull the file, then turn the option back off — it grows unboundedly.

The log lives at one of:

```
/data/misc/bluetooth/logs/btsnoop_hci.log          # Android 8 - 12 (needs root)
/data/misc/bluedroid/btsnoop_hci.log               # older Android
/sdcard/btsnoop_hci.log                            # very old Android
```

With root:

```bash
adb root && adb pull /data/misc/bluetooth/logs/btsnoop_hci.log
```

Without root, take a bugreport and hunt inside it:

```bash
adb bugreport bugreport.zip
unzip -l bugreport.zip | grep -i btsnoop
unzip bugreport.zip '*/btsnoop_hci.log' -d cap/
```

On Android 12+ the file is sometimes omitted from the bugreport unless the
snoop log was already enabled; if it is missing, the rooted path is the only
option.

Notes:

- It is a **ring buffer**. Long sessions wrap and silently lose the beginning,
  which is exactly the part with the connection setup. Keep captures short.
- Some OEM ROMs disable the option entirely.
- The file is `btsnoop`, so Wireshark opens it too — useful for the layers this
  tool does not render (L2CAP signalling, connection parameter updates).

## Linux: btmon

With the band paired to your laptop's adapter:

```bash
sudo btmon -w capture.btsnoop     # start this BEFORE connecting
```

then connect with `bluetoothctl` or `remiband live`. BlueZ writes standard
btsnoop. `hcidump -w` works on older stacks.

## nRF sniffer

An nRF52840 dongle running *nRF Sniffer for Bluetooth LE* with the Wireshark
plugin. It captures the air interface, including the pairing exchange, so it can
follow the encrypted link once it has seen the LTK.

Trade-off: it drops packets under load, so you get gaps and retransmissions. Use
it for the pairing sequence and for timing; use an HCI log for clean command
traffic.

---

## Checklist for a useful capture

The single biggest cause of an unreadable capture is starting it too late.

```
[ ] band disconnected from the phone first
[ ] capture started / snoop log enabled and Bluetooth restarted
[ ] connect from the app            <- connection setup must be IN the capture
[ ] wait ~5 s doing nothing         <- MTU, discovery, subscriptions land here
[ ] do exactly ONE thing
[ ] wait ~5 s
[ ] do it again (twice more)        <- a repeating pattern is easy to spot
[ ] disconnect / force-stop the app
[ ] stop the capture, pull the file
```

Doing the action three times matters: it makes the corresponding frames
obvious, and it distinguishes one-off setup traffic from the thing you did.

Then sanity-check before investigating:

```bash
python3 -m remiband analyze capture.btsnoop
```

You want to see a `peer` address, a discovered `MTU`, a non-empty `SERVICES`
section, and at least some lines in `TIMELINE`. If any of those are missing,
read the table below before going further — the rest of the analysis is not
going to be better than the capture.

For the diff workflow, take a **separate baseline capture** (connect, idle,
disconnect) rather than reusing the same file.

## When the report looks wrong

| Symptom | Cause | Fix |
|---|---|---|
| `not a btsnoop file` | it is a pcap, or a truncated write | re-pull; Wireshark can export/convert |
| `btsnoop file contains no records` | snoop log was never on, or it was cleared | enable, restart Bluetooth, retry |
| no `peer` line | no connection-complete event | start the capture before connecting |
| `SERVICES (0)` | discovery happened before the capture | same |
| handles show `(undiscovered)` | ditto — the handle map comes from discovery | same |
| `AUTHENTICATION NOT OBSERVED` | the app reused a bond and skipped the handshake, or the capture started late | force-stop the app and reconnect; or unpair first |
| frames decode but every id is unresolved | that is normal on a first run | build `labels.json` with `annotate` |
| everything looks like `0xA0` garbage | Zepp OS device (7+) | expected; see docs/protocol.md §6 |

If the file parses but contains only HCI events and no ACL data, the capture
tool was watching the wrong interface — `btmon` on a machine without the
adapter, for instance, will happily write an empty file.

## A note on timestamps

btsnoop timestamps are microseconds since year 0, which is why `remiband` prints
both an absolute ISO time for the first packet and relative offsets thereafter.
Relative offsets are what you reason with; absolutes are for correlating two
captures taken at different times.
