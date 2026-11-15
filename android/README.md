# Sleep guard — an Android app

Play a video before sleep; when you fall asleep, the phone fades the audio out
and pauses the video.

This directory is the phone half of the project. The `remiband/` Python package
at the repository root is the research half: it decodes captures, which is where
the protocol facts here come from.

---

## Status

**Not compiled.** This was written in an environment with no Android SDK, so
`./gradlew assembleDebug` has never run against it. Treat the first build as a
code review, not a formality — see [Known gaps](#known-gaps).

The **detector algorithm is verified**, though not in Kotlin: it was ported to
Python and run against eight scenarios (fires once when asleep, never while
awake-but-still, cancelled by a heart-rate rise, cancelled by restlessness,
needs a real baseline). That check is what caught a genuine bug — see
[the median-lag bug](#the-median-lag-bug).

## What it actually does

```
                 ┌───────────────────┐
  Mi Band ──BLE──▶ heart rate + motion ──▶ SleepDetector ──▶ "asleep?"
                 └───────────────────┘                       │
                                                             ▼
  Bilibili / YouTube / Douyin ──MediaSession──▶ fade 20s ──▶ pause
```

Two arming modes, and they compose:

| Mode | Signal | Works today? |
|---|---|---|
| **Timer** | minutes of *actual playback* (paused video costs nothing) | **yes**, any phone |
| **Band** | heart rate + wrist motion → `SleepDetector` | only on a band whose protocol we can speak |

The timer is not a pretend-smart fallback. It is the guarantee that the video
does not play until morning — which is the actual harm — while the band path is
still being finished.

## The honest part: why the band is not wired up on a Mi Band 10

Detecting sleep from the phone alone does not work, and it is worth being
precise about why, because it is the reason the band is in the design at all:

- **Touch-based inactivity false-pauses.** Watching a video involves no
  touches. A "pause after 10 minutes of no interaction" rule fires on someone
  who is wide awake, twenty minutes into a video.
- **The screen stays on** while a video plays, so screen-off is not a signal
  either.
- **A wrist sensor can** distinguish "awake and motionless" from "asleep",
  because heart rate settles and gross motion stops.

So the band is not decorative — it is the only sensor that can observe the body
rather than the phone. And that is exactly the data blocked by the unverified
Mi Band 10 protocol (see `../docs/protocol.md` §7).

The app therefore does not guess. In band mode, with no usable heart rate, the
detector reports *"waiting for heart-rate data"* and never fires; the timer keeps
protecting you. Once a capture tells us where the heart rate lives, this becomes
one line of configuration rather than a rewrite.

## Build

Android Studio (Hedgehog or newer) → **Open** → this `android/` directory →
Run. Or from the command line:

```bash
cd android
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest     # detector + protocol tests, no device needed
```

No dependencies beyond JUnit for tests — plain `android.*` only, no AndroidX, no
Compose, no coroutines. The UI is built programmatically and is consequently
plain-looking; the trade is that nothing can drift out of version compatibility.

## First run — the two grants people forget

1. **Notification access.** Settings → *Notification access* → enable **Sleep
   guard**. The app does not read notifications; this is the framework's gate
   for `MediaSessionManager.getActiveSessions`, i.e. for being allowed to pause
   another app. Without it, only the media-key fallback works (which some
   players ignore).
2. **Battery optimisation.** Exempt the app, or the OEM task killer will end the
   service mid-video. This matters most on Xiaomi/Huawei/Oppo devices — the very
   phones this is for.

Then: set *playback min*, press **Start watching**. The status line shows what
the detector is thinking, live.

## The median-lag bug

Worth documenting because it is the kind of thing that survives a code review.

Settling used a 3-minute rolling **median** of heart rate. Waking used the same
median. But a median lags a change by up to a full window, so there was a gap —
up to three minutes — in which the user had already woken and the median still
showed the sleeping value. The confirm timer could expire inside that gap and
pause a video on someone looking at the screen.

The fix is deliberate asymmetry:

| Question | Signal | Why |
|---|---|---|
| *has the user settled?* | median over 3 min | a decision to **act** must be slow and stable |
| *has the user woken?* | **max** over 90 s | a decision to **not act** must be fast |

Failing to pause is a minor annoyance. Pausing wrongly is the bug that makes
people uninstall the app.

## Known gaps

- Not compiled; expect to fix small things on first build.
- Band mode assumes the classic Mi Band 2–6 protocol (`0xA0` envelope, heart
  rate on `ff12`, auth on `00000009-…`). On a Mi Band 10 there may be **no**
  `ff12` characteristic; the app says so and stays on the timer.
- The heart-rate **byte offset** is a setting, not a constant, because the frame
  layout is unverified. Default `-1` means "log it and look" rather than "read a
  byte and hope". The probe screen shows the raw notifications so you can find
  it from a capture.
- No resume-after-awake. Waking up does not restart the video, by design: you
  are asleep, and an automatic resume is a worse failure than staying paused.
- Fade uses the *music* stream. If the video app uses its own stream the fade
  may not apply; the pause still does.

## Layout

```
app/src/main/java/dev/remiband/
  core/Hex.kt              hex parsing/formatting
  core/Crypto.kt           AES-128 ECB (platform javax.crypto)
  core/MibandProtocol.kt   0xA0 envelope + auth state machine
  ble/BleCentral.kt        scan/connect/GATT, serialised operation queue
  sleep/SleepDetector.kt   the decision logic — pure Kotlin, no Android
  sleep/MediaGate.kt       MediaSession pause + volume fade
  sleep/Settings.kt        single source of defaults
  sleep/SleepWatchService.kt   foreground service, both modes
  sleep/SleepGuardActivity.kt  main screen
  probe/ProbeActivity.kt   protocol-agnostic explorer (the MB10 tool)
app/src/test/java/dev/remiband/
  sleep/SleepDetectorTest.kt   8 scenarios
  core/ProtocolTest.kt         framing, hex, AES, auth
```

## Tuning

Every threshold is in `SleepDetector.Config`, in one place:

```kotlin
SleepDetector.Config(
    drowsyQuietMs = 6 * 60_000,      // start considering
    sleepQuietMs = 10 * 60_000,      // quiet before onset is possible
    confirmMs = 4 * 60_000,          // must hold this long
    heartRateDropFraction = 0.06,    // 6% below your awake baseline
    requireHeartRate = true,         // never fire without a heart rate
)
```

Adjust after a few nights. **When in doubt, make it slower**: a late pause costs
a little battery, a wrong pause costs your evening.
