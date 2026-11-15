# The Mi Band BLE link

What is known, what is inferred, and what to check in your own capture.

## Confidence key

Every claim below is tagged, because a protocol document that mixes verified
facts with folklore is worse than no document at all.

| Tag | Means |
|---|---|
| **certain** | from the Bluetooth specification or a spec-defined UUID; not Mi-Band-specific |
| **high** | consistent across multiple independent implementations, and the analyzer will confirm or refute it from your capture in one run |
| **medium** | reported by more than one source but varies by model/firmware; check your capture |
| **low** | a hypothesis. Treat it as a question, not an answer |

The tool never depends on a **medium** or **low** claim: it decodes structure
(which is **high**) and prints raw ids for semantics (which is not).

---

## 1. The four layers

A capture is read bottom-up. Each layer has its own failure mode, so it is worth
knowing which one you are looking at.

```
HCI        connection setup, pairing events, when encryption came up
 └ L2CAP   channels: ATT (4), LE signalling (5), SMP (6)
    └ ATT  requests/responses/notifications per attribute handle
       └ Mi Band   0xA0-framed commands inside attribute values
```

`remiband` walks all four and prints them as one timeline.

## 2. Connection lifecycle

The order below is what the timeline shows for a normal session. **high**

1. **Advertising.** The band advertises a complete local name (AD type `0x09`)
   such as `Mi Smart Band 4`, plus Xiaomi service data under UUID `0xFE95`
   (the "MiBeacon" format). The product id lives in that service data and is
   how a client picks a model-specific protocol. **medium** — the `0xFE95`
   wrapper is **high**, the exact product-id offset is **medium**.

2. **LE connection.** Peripheral role, one ACL handle for the session.

3. **Pairing (SMP).** Just Works, no MITM: the band has no keyboard or display,
   so it reports IO capability `NoInputNoOutput`. It bonds, distributing a
   16-byte LTK plus EDIV/Rand. Consequences worth knowing:
   - there is no meaningful "pairing code" to intercept;
   - the bond is what makes reconnection silent later;
   - an over-the-air sniffer needs the LTK (captured during pairing) to decrypt
     anything after this point. **certain** (SMP mechanics), **high** (that the
     band uses Just Works).

4. **Link encryption on.** HCI `Encryption Change` event, enabled.
   Note: an *HCI snoop log* on the phone is taken above the controller, so it
   shows plaintext ATT even though the air interface is encrypted. That is a
   large advantage over sniffing the air.

5. **ATT MTU exchange.** The phone proposes, the band answers with its maximum.
   Real bands commonly sit at 185 or 247; whatever it is, it sets how many
   payload bytes fit in one command chunk.

6. **GATT discovery.** Primary services, then characteristics per service
   range, then descriptors. This is where the handle map comes from — and it is
   the most valuable thing in the capture.

7. **CCCD writes.** Subscribing to the notify characteristics. In the official
   app this is a clean list of "what it listens to", which is a strong hint
   about which handles carry the interesting traffic.

8. **Authentication.** See §5.

9. **Command traffic.** See §4.

### Typical attribute map

**high** for the service and the auth characteristic; **medium** for the
individual `0xFFxx` names, which vary by model.

| UUID | Role |
|---|---|
| `00001800` / `00001801` / `0000180a` / `0000180f` / `0000180d` | standard: Generic Access, GATT, Device Information, Battery, Heart Rate |
| `0000fee0-…` | Mi Band main service; characteristics `0000ff01`…`0000ff14` |
| `0000fee1-…` | Mi Band auth service |
| `00000009-0000-3512-2118-0009af100700` | **the auth characteristic** (inside `fee1`) |

The `…-0000-3512-2118-0009af100700` suffix is the Xiaomi 128-bit base: it is
what makes a Xiaomi UUID recognisable at a glance in a hex dump.

Selected `0xffXX` on `fee0`, **medium**:

| UUID | Reported role |
|---|---|
| `ff01` | device info |
| `ff02` | device name |
| `ff03` | notification / reply channel |
| `ff04` | user info |
| `ff05` | **control point** (commands are written here) |
| `ff06` | realtime steps |
| `ff0c` | battery |
| `ff11` / `ff12` | heart rate control / data |
| `ff13` | auth (legacy) |

Which handle carries replies is model-dependent — and it does not matter, since
the analyzer attributes every observed handle automatically instead of assuming.

## 3. The `0xA0` envelope

Every Mi Band application message is wrapped in a 4-byte header. **high** for
the structure.

**Phone → band** (written to the control point):

```
a0 | cmd | seq | len | payload[len]
```

**Band → phone** (notification):

```
a0 | 01 | type | status | payload
```

- `seq` starts at 0 and increments for each following chunk.
- `len` is the byte count in *that* chunk, not the total.
- With a 20-byte ATT value, payload capacity is 16 bytes, so anything longer is
  split. A chunk shorter than 16 bytes is the last one — that single rule is
  enough to reassemble, and it is what `miband.ChunkAssembler` uses.
- `status` `0x01` reads as success and `0x00` as failure. **medium** — the
  convention is widely reported, and `status` is at least always in that byte
  position.

**Command ids are not documented here on purpose.** They are model-specific and
the community tables disagree. The method in §8 is how you establish them
instead of trusting a list.

## 4. Authentication

On Mi Band 3 and later the command channel is locked until an AES-128
challenge/response completes. **high** for 3/4; **medium** for 5/6; **low** for
7/8, which move to a chunked scheme (commonly reported on `00000016-…`).

All traffic in this section is on `00000009-0000-3512-2118-0009af100700`.
Control notifications from the band start with `0x10`.

```
# the band announces it wants auth (sometimes only after the phone starts)
band -> phone   10 01 01                    "ready"

# the phone starts, then asks for a nonce
phone -> band   01 08                       start auth
phone -> band   02 00                       request nonce

# the band sends a 16-byte challenge
band -> phone   10 02 01 <16-byte nonce>

# the phone answers with AES-128-ECB(key, nonce)
phone -> band   03 00 <16-byte ciphertext>

# verdict
band -> phone   10 03 01                    authenticated
band -> phone   10 03 00                    rejected
```

Notes that save time:

- `AES-128-ECB`, no padding, one block. That is the entire primitive — which is
  why `remiband/aes.py` is 150 lines and has no dependencies.
- Some firmware writes the response as a bare 16 bytes without the `03 00`
  prefix. The analyzer prints what your capture actually contains and tells you
  which it saw, so you do not have to trust this document.
- A `10 03 00` means wrong key. There is no retry negotiation: reconnect.

### The key cannot be recovered from a capture

This is the single most important thing to understand, and it is a common
misconception.

The capture contains one (plaintext nonce, ciphertext) pair. AES-128 with one
known pair is not invertible by any practical means — recovering the key would
require breaking AES. **certain.**

So the key has to come from somewhere else.

## 5. Where the key comes from

Three routes, in order of practicality.

**1. Provision your own. (recommended)** The key is not burned into the band at
the factory: the phone *chooses* it and stores it. After a factory reset the
band has none, so the first pairing provisions whatever the client sends. This
is why self-hosted implementations can work with a key you generated yourself.

The provisioning write happens during that first-ever pairing, in your capture,
between the SMP bond and the first authenticated command. Locate it with:

```bash
python3 -m remiband diff before-pairing.btsnoop during-pairing.btsnoop
```

**2. Extract the key the official app already holds.** It is fetched from
Xiaomi's cloud per-account and cached on the device, so it can be recovered from
the app's storage on a rooted phone (or by observing the account's own API
traffic). Use your own account and your own device.

**3. Reuse a key you already know** from a previous pairing of the same device.

What does *not* work: guessing, brute force, or deriving it from the handshake.

Note also that the key protects **commands**, not confidentiality of the
attribute table: device name, model, firmware, battery and the heart-rate
stream all read fine unauthenticated. That is why so much is learnable from a
capture that never authenticates.

## 6. Model differences

| Family | Notes | Confidence |
|---|---|---|
| Mi Band 2 | `fee0` service; early firmware has no secure command channel at all | **medium** |
| Mi Band 3 / 4 | the layout in this document; auth on `00000009` | **high** |
| Mi Band 5 / 6 | same shape plus extra characteristics; mostly compatible | **medium** |
| Mi Band 7+ / Zepp OS | different: chunked, encrypted transport, auth often on `00000016-…`; a `0xA0`-only decoder will under-read it | **low–medium** |
| **Mi Band 9 / 10** | **not described here.** Newer generation; assume chunked transport plus encryption above BLE. See §7 before writing any code | **unverified** |

The analyzer does not care: it reports the services, handles and channels a
given device actually exposes, then decodes `0xA0` where it appears. For Zepp OS
devices expect more raw bytes and fewer decoded frames — that is the signal that
you are looking at the newer protocol, not a bug.

## 7. If your device is newer than this document

Mi Band 7 and later — and anything newer than the generation this document was
written against — may not speak the `0xA0` envelope at all. Do not assume;
measure:

```bash
python3 -m remiband survey capture.btsnoop
```

`survey` makes no protocol assumptions. It prints every handle that carried
traffic, the block sizes, raw hex, and scores four framing hypotheses against
the bytes actually observed, each with its evidence:

| Verdict | Means | What to do |
|---|---|---|
| `classic-a0` | §3 and §4 apply | use `frames`, then `annotate` |
| `chunked` | fixed-size blocks with a running counter — the newer transport shape | the evidence names the block size and the counter offset; that offset is the first field of the new envelope |
| `opaque` | high entropy, no structure — encryption **above** BLE link encryption | find the session key exchange in the capture first |
| `unknown` | not enough traffic | capture a connect plus one action, not just a name write |

A `chunked` or `opaque` verdict is a successful result, not a failure: it tells
you the `0xA0` decoder does not apply, which is the expensive mistake to avoid.
Zero decoded frames with a `classic-a0` verdict would be the alarming case.

Then continue with the diff method in §8 — it is protocol-agnostic and works
whatever the envelope turns out to be.

### Mi Band 10 specifically

There is no verified public description of the Mi Band 10 protocol that this
toolkit can vouch for, so **nothing here asserts its byte layout**. What can be
said responsibly:

- it is a Xiaomi device, so the 128-bit UUID base
  (`…-0000-3512-2118-0009af100700`) and service `0xfee0` are likely still
  present — the fingerprint will confirm;
- the `0xA0` envelope in §3 is a Mi Band 2–6 generation format; a 10 very
  likely does not use it unchanged;
- expect a chunked transport *and* an encryption layer above BLE, which means
  the secret you need is a **session key**, not only the 16-byte auth key of §4.

With the device in hand, in order:

1. get the attribute table — `remiband live --scan` on a machine with a radio,
   or an Android HCI snoop log; the service/characteristic set identifies the
   protocol family;
2. `remiband survey` on that capture: block size, counter offset, entropy;
3. `remiband diff` between a baseline and one action.

None of those three steps needs the protocol known in advance. That is the
point of doing them first.

## 8. How to establish the command ids

Do not start from a list. Establish them:

1. Capture a baseline: connect, idle 10 s, disconnect.
2. Do **one** thing in the official app.
3. Capture again, then `remiband diff base.btsnoop after.btsnoop`.
4. Note the new ids. For a new id, read its payload shape:
   `remiband frames after.btsnoop --labels labels.json`.
5. Change exactly one variable and diff again. Bytes that move are the value;
   bytes that stay are the structure.
6. Record it: `remiband annotate after.btsnoop --cmd 0x1a --name "set alarm"`.

Repeat for the behaviours you care about. Each iteration turns one unknown into
one finding, and `labels.json` accumulates them so later captures decode
readably.

Useful heuristics the tool already applies, because they are testable rather
than guessed:

- a payload starting with a little-endian year in 1980..2200 is timestamp-like;
- an ASCII/UTF-8 run is text (notifications, contact names, alarm labels);
- one or two bytes is a scalar (a selector, an index, a battery level).

## 9. What to look at first

If you only want the connection working, in order of payoff:

1. `services` — the handle map, which never changes for a given model.
2. `auth` — confirm the handshake shape before implementing anything.
3. `timeline` — the ordering, especially the CCCD subscriptions, tells you
   which handles the vendor considers the important ones.
4. `frames` + `diff` — the actual commands, once you need them.

## References

- Bluetooth Core Specification, Vol 3 Part F (ATT) and Vol 3 Part H (SMP).
- btsnoop file format (Symbian/Apple/BlueZ lineage; Wireshark's `wiretap`).
- The Gadgetbridge project is the largest open corpus of Mi Band protocol work
  and is the natural cross-check for any claim here.
