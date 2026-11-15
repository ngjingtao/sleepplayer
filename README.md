# REMiBand

A reverse-engineering workbench for the Xiaomi Mi Band BLE link.

Point it at a capture from your own phone or laptop and it reconstructs the
whole connection — advertising, pairing, GATT discovery, the AES
challenge/response, and the `0xA0`-framed command channel — without the band,
the official app, or a radio.

```
$ python3 -m remiband demo
==============================================================================
 REMiBand analysis
==============================================================================
 file      /tmp/remiband_demo.btsnoop
 records   70   span 0.756 s   datalink 1002 (HCI UART)
 ...
 LINK
   peer      C2:4F:90:11:22:33  "Mi Smart Band 4"
   link      handle 0x0040   MTU 185   encryption on

 AUTHENTICATION
   result    PASS - command channel unlocked in this capture
   key       16 bytes supplied - consistent with capture
      0.414s  band->app  auth ready (10 01 01)
      0.434s  app->band  start auth (01 08)
      0.458s  app->band  request nonce (02 00)
      0.482s  band->app  nonce (10 02 01 00112233445566778899aabbccddeeff)
      0.502s  app->band  challenge response (03 00 69c4e0d8...)
      0.526s  band->app  AUTHENTICATED (10 03 01)
```

**中文说明：[README.zh.md](README.zh.md)**

## Two halves

| Half | What it does | Needs |
|---|---|---|
| `remiband/` (Python) | decodes captures, identifies the transport, diffs sessions | nothing but Python 3.9+ |
| `android/` (Kotlin) | **Sleep guard**: fades audio out and pauses your video when you fall asleep | a phone; a band for the smart path |

No JDK or Android SDK is available in the environment this was written in, so
the APK is built by CI rather than locally:
[.github/workflows/build-apk.yml](.github/workflows/build-apk.yml) builds and
tests on every push and uploads an installable `sleepplayer-*.apk`.

The app is the goal; the capture tooling is how its protocol facts get
established. See [android/README.md](android/README.md).

## Why a capture is the right primitive

Everything interesting about the Mi Band link lives at one of four layers, and
a single `btsnoop` file carries all four:

| Layer | What you learn |
|---|---|
| HCI | what the phone asked the controller to do, connection parameters, when encryption came up |
| L2CAP / SMP | how pairing happened, whether it was Just Works, whether an LTK was bonded |
| ATT / GATT | **every handle and UUID on the device**, recovered from the discovery replies |
| Mi Band | the `0xA0` command/reply traffic and its pacing |

The GATT layer is the useful trick: you only need *one* capture of the official
app connecting to learn the complete attribute table, and those handles stay
stable across sessions. After that you can talk to the device from a laptop
with nothing but a UUID table.

## Quickstart

No hardware, no dependencies — the whole toolkit is stdlib Python 3.9+:

```bash
python3 -m remiband demo            # synthetic capture, proves the toolchain
python3 -m unittest discover -s tests -t .
```

On a real capture:

```bash
python3 -m remiband analyze capture.btsnoop          # full report
python3 -m remiband services capture.btsnoop         # just the attribute table
python3 -m remiband frames capture.btsnoop           # just the 0xA0 messages
python3 -m remiband auth capture.btsnoop --key <32 hex>
python3 -m remiband analyze capture.btsnoop --json    # for scripting
```

Getting the capture is the only part that needs a device — see
[docs/capture.md](docs/capture.md).

## The reverse-engineering loop

The point of the tool is this cycle, made executable:

```bash
# 1. baseline: connect, let it idle, disconnect
python3 -m remiband analyze baseline.btsnoop

# 2. do exactly ONE thing in the official app (set an alarm, start a workout)
# 3. capture again, then diff
python3 -m remiband diff baseline.btsnoop after.btsnoop
```

```
 NEW IN b (added by whatever you did)  [2]
   command  0x1a   1 frame(s)
   response 0x1a   1 frame(s)

 SAME ID, DIFFERENT BYTES  [1]
   command  0x0a
     a: 48 65 6c 6c 6f 20 66 72 6f 6d 20 4d 69 42 61 6e 64 21
     b: 41 6c 61 72 6d 20 30 37 3a 33 30 20 73 65 74
        first difference at byte 0: 0x48 -> 0x41
```

Then name what you found, and the label persists across analyses:

```bash
python3 -m remiband annotate after.btsnoop --cmd 0x1a --name "set alarm"
python3 -m remiband analyze after.btsnoop --labels labels.json
```

Change one variable at a time (a different alarm time, a longer contact name)
and diff again — that is what separates a field's *position* from its *value*,
and it is the only thing that turns a guess into a finding.

## Commands

| Command | Purpose |
|---|---|
| `analyze` | full report: link, protocol, auth, services, channels, frames |
| `survey` | **no protocol assumptions** — raw traffic + framing hypotheses |
| `services` | recovered attribute table with live values |
| `frames` | decoded `0xA0` messages, chunked commands reassembled |
| `timeline` | one line per event: connect, MTU, subscribe, SMP, auth |
| `auth` | the handshake only; verifies a key against the capture |
| `diff` | compare two captures to isolate one user action |
| `annotate` | give a command id a name, persisted as JSON |
| `demo` | build a synthetic capture and analyse it |
| `live` | talk to a real band — needs `pip install bleak` + a radio |

On a device newer than the classic protocol — Mi Band 7 and up, including a
**Mi Band 10** — run `survey` first. It reports `chunked` or `opaque` instead of
silently decoding nothing, and tells you the block size and counter offset to
build the new envelope from. See [docs/protocol.md §7](docs/protocol.md).

`live` is the only component that has not been run against hardware; this
toolkit was developed in a container with no Bluetooth adapter. It is written
to fail loudly rather than pretend, and everything else is covered by tests.

## What is verified, and what is not

Being precise about this matters more than the feature list.

**Verified here** (63 unit tests, `python3 -m unittest discover -s tests -t .`):

- AES-128 against the FIPS-197 and NIST SP 800-38A vectors
- btsnoop framing, including the 64-bit microsecond timestamp
- HCI ACL fragment reassembly and ATT PDU decoding
- GATT reconstruction from discovery replies, for both 16-bit and 128-bit UUIDs
- Mi Band envelope decoding and multi-chunk reassembly
- the auth state machine, including detecting a key that does *not* match
- end-to-end: synthetic HCI bytes in, device model out
- capture diffing

**Not verified here:**

- behaviour against a real band — no radio in this environment
- semantic meanings of most command ids. The decoder deliberately reports
  `cmd=0x13` rather than inventing a name; the two seeded labels are marked
  low/medium confidence and always printed next to the raw id.
- the `live` client

**Confidence levels** for the protocol itself are tabulated in
[docs/protocol.md](docs/protocol.md).

## Layout

```
remiband/
  aes.py           AES-128 ECB, pure Python, no deps
  btsnoop.py       btsnoop reader/writer + HCI packet splitting
  att.py           ATT decode + GATT table reconstruction
  miband.py        envelope codec, chunk reassembly, auth state machine
  analyze.py       the walk: capture -> session model
  render.py        human-readable report
  compare.py       capture diffing
  uuids.py         UUID names for the standard and Xiaomi namespaces
  live.py          bleak client (hardware; unverified)
  demo_capture.py  synthetic fixture generator
  cli.py           command line
docs/
  protocol.md      the protocol, with confidence levels
  capture.md       how to get a capture from Android / Linux / a sniffer
tests/             63 tests
android/           Sleep guard app (Kotlin), with its own README
```

## Legal and ethical scope

## The sleep app in one paragraph

Play a video before bed; when you fall asleep the phone fades the audio out over
20 seconds and pauses it. Pausing is easy and works today. *Knowing* you are
asleep is the hard half, and it is why the band is in the design: a phone cannot
tell "awake and motionless" from "asleep" because watching a video involves no
touches. Heart rate settling below your baseline plus wrist motion stopping can.
On a Mi Band 10 that data is still behind the unverified protocol, so the app
ships a playback-aware timer as the guarantee, and the detector waits —
reporting "waiting for heart-rate data" rather than guessing.

## Legal and ethical scope

This is for interoperability with hardware you own. The auth key is a
per-device secret; see [docs/protocol.md](docs/protocol.md) for the legitimate
routes to one (provision your own after a factory reset is the clean path).
Do not use this to read other people's devices.
