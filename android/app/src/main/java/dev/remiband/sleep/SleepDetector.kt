package dev.remiband.sleep

/**
 * Decides whether the user has fallen asleep, from the signals that are
 * available at the time.
 *
 * This class is deliberately free of Android imports: it takes timestamps and
 * values, returns a decision, and can therefore be tested on the JVM in
 * milliseconds instead of on a phone over hours.
 *
 * ## Why it needs the band
 *
 * The tempting shortcut is "pause when the phone has not been touched for ten
 * minutes". It does not work: watching a video involves no touches, so the
 * timer fires while the user is wide awake, twenty minutes in. Phone-side
 * signals cannot separate "awake and motionless" from "asleep".
 *
 * A wrist sensor can. Heart rate settling below a personal baseline and gross
 * motion stopping are the two things that actually differ, which is why
 * [Config.requireHeartRate] defaults to true: with no heart-rate data the
 * detector will not fire at all. It reports "waiting for heart rate" rather
 * than guessing, and the app falls back to the explicit timer instead.
 *
 * ## Thresholds
 *
 * The defaults are starting values chosen to be conservative, not tuned on the
 * user. They live in one place so they can be adjusted after a few nights:
 * false pauses are much worse than a late pause, so when in doubt, make it
 * slower.
 */
class SleepDetector(private val config: Config = Config()) {

    data class Config(
        /** Quiet for this long and we start considering it. */
        val drowsyQuietMs: Long = 6 * 60_000L,
        /** Quiet for this long before onset can be confirmed (needs motion). */
        val sleepQuietMs: Long = 10 * 60_000L,
        /**
         * Warm-up when the device reports no motion at all.
         *
         * The heart-rate characteristic of a Mi Band exposes pulse and skin
         * contact, not movement, so this app often has no stillness signal.
         * Pretending otherwise would be a lie in the logs: the "quiet" counter
         * would just be elapsed time. When no motion event has ever arrived,
         * onset is judged from heart rate alone, gated behind this warm-up so
         * the baseline has time to be learned.
         */
        val minSessionMs: Long = 10 * 60_000L,
        /** Conditions must hold continuously for this long. */
        val confirmMs: Long = 4 * 60_000L,
        /** Window at the start of the session used to learn the awake HR. */
        val baselineWindowMs: Long = 10 * 60_000L,
        val minBaselineSamples: Int = 5,
        /** Fractional fall below baseline that counts as "settling". */
        val heartRateDropFraction: Double = 0.06,
        /** Fractional rise above baseline that means "awake again". */
        val heartRateWakeFraction: Double = 0.02,
        /** Rolling window for the current heart rate. */
        val heartRateWindowMs: Long = 3 * 60_000L,
        /** Window for spotting that the user has woken up again. */
        val heartRateWakeWindowMs: Long = 90_000L,
        /** Motion at or above this level counts as "moved". */
        val wakeMotionLevel: Int = 2,
        /** After significant motion, onset is blocked this long. */
        val wakeMotionWindowMs: Long = 2 * 60_000L,
        /** With no heart rate, never fire. True is the safe default. */
        val requireHeartRate: Boolean = true,
    )

    enum class Phase { AWAKE, DROWSY, ASLEEP }

    data class Status(
        val phase: Phase,
        val quietMs: Long,
        val heartRate: Int?,
        val baseline: Int?,
        val heldMs: Long,
        val fired: Boolean,
        val reason: String,
    )

    private data class Sample(val ts: Long, val bpm: Int)

    private val hr = ArrayDeque<Sample>()

    private var startMs = -1L
    private var lastInteractionMs = -1L
    private var lastMotionMs = -1L
    private var lastWakeMotionMs = -1L
    private var conditionsMetSinceMs = -1L
    private var phase = Phase.AWAKE
    private var fired = false
    private var motionEvents = 0
    private var reason = "not started"

    val isRunning: Boolean get() = startMs >= 0L

    fun start(nowMs: Long) {
        startMs = nowMs
        lastInteractionMs = nowMs
        lastMotionMs = nowMs
        lastWakeMotionMs = nowMs
        conditionsMetSinceMs = -1L
        phase = Phase.AWAKE
        fired = false
        motionEvents = 0
        reason = "started; learning your awake heart rate"
        hr.clear()
    }

    fun stop() {
        startMs = -1L
        hr.clear()
        conditionsMetSinceMs = -1L
        phase = Phase.AWAKE
        reason = "stopped"
    }

    // ------------------------------------------------------------- signals

    /** The user touched or unlocked the phone. Weak evidence, but free. */
    fun onInteraction(nowMs: Long) {
        if (nowMs > lastInteractionMs) {
            lastInteractionMs = nowMs
            reason = "interaction"
        }
    }

    /**
     * Wrist motion. Level 0 means "still"; 1..2 is movement; >= [Config.wakeMotionLevel]
     * means the user actually shifted, which blocks onset for
     * [Config.wakeMotionWindowMs].
     */
    fun onMotion(nowMs: Long, level: Int) {
        if (level >= 1) {
            motionEvents++
            if (nowMs > lastMotionMs) lastMotionMs = nowMs
        }
        if (level >= config.wakeMotionLevel && nowMs > lastWakeMotionMs) {
            lastWakeMotionMs = nowMs
            reason = "movement detected (level $level)"
        }
    }

    fun onHeartRate(nowMs: Long, bpm: Int) {
        if (bpm !in 25..250) return
        hr.addLast(Sample(nowMs, bpm))
        while (hr.size > 2048) hr.removeFirst()
    }

    // ---------------------------------------------------------------- tick

    /**
     * Advance the state machine. Call about once a minute.
     *
     * @return true exactly once, at the moment onset is confirmed.
     */
    fun tick(nowMs: Long): Boolean {
        if (startMs < 0L) return false
        prune(nowMs)

        val quiet = nowMs - maxOf(lastInteractionMs, lastMotionMs)
        val hasMotion = motionEvents > 0
        val elapsed = nowMs - startMs
        // With a motion signal, "still" is real. Without one, the only honest
        // statement is "the session has been running long enough".
        val quietOk = if (hasMotion) quiet >= config.sleepQuietMs
                      else elapsed >= config.minSessionMs
        val baseline = baselineHeartRate()
        val current = currentHeartRate(nowMs)

        val hrDropped = heartRateDropped(current, baseline)
        val hrRising = heartRateRising(nowMs, baseline)
        val motionOk = nowMs - lastWakeMotionMs >= config.wakeMotionWindowMs

        val met = quietOk && hrDropped && motionOk && !hrRising

        if (met) {
            if (conditionsMetSinceMs < 0L) conditionsMetSinceMs = nowMs
            phase = Phase.DROWSY
            val held = nowMs - conditionsMetSinceMs
            reason = buildString {
                if (hasMotion) append("quiet ${quiet / 60_000}m")
                else append("heart-rate only, ${elapsed / 60_000}m in")
                if (current != null && baseline != null) append(", HR $current/$baseline")
                append(", confirmed ${held / 60_000}/${config.confirmMs / 60_000}m")
            }
            if (!fired && held >= config.confirmMs) {
                fired = true
                phase = Phase.ASLEEP
                reason = "sleep onset confirmed"
                return true
            }
        } else {
            conditionsMetSinceMs = -1L
            phase = if (quiet >= config.drowsyQuietMs) Phase.DROWSY else Phase.AWAKE
            reason = explainNotMet(
                quiet, elapsed, hasMotion, current, baseline, hrDropped, hrRising, motionOk, nowMs
            )
        }
        return false
    }

    fun status(nowMs: Long): Status {
        val quiet = if (startMs < 0L) 0L else nowMs - maxOf(lastInteractionMs, lastMotionMs)
        val held = if (conditionsMetSinceMs < 0L) 0L else nowMs - conditionsMetSinceMs
        return Status(
            phase = phase,
            quietMs = quiet,
            heartRate = currentHeartRate(nowMs),
            baseline = baselineHeartRate(),
            heldMs = held,
            fired = fired,
            reason = reason,
        )
    }

    val hasFired: Boolean get() = fired

    // ------------------------------------------------------------- helpers

    private fun prune(nowMs: Long) {
        val horizon = nowMs - 30 * 60_000L
        while (hr.isNotEmpty() && hr.first().ts < horizon) hr.removeFirst()
    }

    /**
     * The user's awake heart rate, measured only in the first
     * [Config.baselineWindowMs] of the session. Using the whole session would
     * let the baseline drift down with the user and erase the very signal we
     * are looking for.
     */
    private fun baselineHeartRate(): Int? {
        if (startMs < 0L) return null
        val cutoff = startMs + config.baselineWindowMs
        val values = hr.asSequence().filter { it.ts <= cutoff }.map { it.bpm }.toList()
        if (values.size < config.minBaselineSamples) return null
        return median(values)
    }

    private fun currentHeartRate(nowMs: Long): Int? {
        val cutoff = nowMs - config.heartRateWindowMs
        val values = hr.asSequence().filter { it.ts >= cutoff }.map { it.bpm }.toList()
        if (values.isEmpty()) return null
        return median(values)
    }

    private fun heartRateDropped(current: Int?, baseline: Int?): Boolean {
        if (current == null || baseline == null) return !config.requireHeartRate
        return current <= baseline * (1.0 - config.heartRateDropFraction)
    }

    /**
     * "Has the user woken up?" -- deliberately asymmetric with
     * [heartRateDropped].
     *
     * Settling is a decision to *act*, so it uses the rolling median and must
     * be slow and stable. Waking is a decision to *not* act, so it uses the
     * newest sample and must be fast. With the median on both sides there is a
     * gap of up to one window where the user is already awake but the median
     * still shows the sleeping value -- long enough for the confirm timer to
     * expire and pause a video on someone who is looking at the screen.
     */
    private fun heartRateRising(nowMs: Long, baseline: Int?): Boolean {
        if (baseline == null) return false
        val recent = hr.asSequence()
            .filter { it.ts >= nowMs - config.heartRateWakeWindowMs }
            .maxOfOrNull { it.bpm } ?: return false
        return recent >= baseline * (1.0 + config.heartRateWakeFraction)
    }

    private fun median(values: List<Int>): Int {
        val sorted = values.sorted()
        return sorted[sorted.size / 2]
    }

    private fun explainNotMet(
        quiet: Long,
        elapsed: Long,
        hasMotion: Boolean,
        current: Int?,
        baseline: Int?,
        hrDropped: Boolean,
        hrRising: Boolean,
        motionOk: Boolean,
        nowMs: Long,
    ): String = when {
        !hasMotion && elapsed < config.minSessionMs ->
            "heart-rate only: warming up ${elapsed / 60_000}/${config.minSessionMs / 60_000}m"
        config.requireHeartRate && current == null ->
            "waiting for heart-rate data (band path unavailable)"
        hrRising && current != null && baseline != null ->
            "heart rate is up ($current/$baseline) - you are awake"
        !hrDropped && current != null && baseline != null ->
            "heart rate has not settled ($current/$baseline)"
        !motionOk ->
            "movement ${(nowMs - lastWakeMotionMs) / 1000}s ago"
        else -> "active ${quiet / 60_000}m ago"
    }
}
