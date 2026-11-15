package dev.remiband.sleep

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The detector is the part that can be wrong in a way that annoys the user, so
 * it is the part with tests. These run on the JVM with no device:
 *
 *     ./gradlew :app:testDebugUnitTest
 *
 * The scenarios are the real disagreements: "still awake and watching" must not
 * fire, "asleep" must fire exactly once, and "nodded off then moved" must not.
 */
class SleepDetectorTest {

    private val step = 30_000L
    private val minute = 60_000L

    @Test
    fun `does not fire without heart rate when heart rate is required`() {
        val detector = SleepDetector()
        detector.start(0L)

        var fired = false
        var t = 0L
        while (t <= 40 * minute) {
            if (detector.tick(t)) fired = true
            t += step
        }

        assertFalse("an inactivity-only detector would false-pause here", fired)
        assertTrue(
            "the reason must say why it is waiting",
            detector.status(t).reason.contains("heart-rate"),
        )
    }

    @Test
    fun `fires when heart rate settles and movement stops`() {
        val detector = SleepDetector()
        detector.start(0L)

        var t = 0L
        // Twenty minutes awake: resting HR, occasional small movement.
        while (t <= 20 * minute) {
            detector.onHeartRate(t, 62)
            if (t in 1..(10 * minute) && t % (2 * minute) == 0L) detector.onMotion(t, 1)
            detector.tick(t)
            t += step
        }

        // Then asleep: heart rate drops, no motion.
        var firedAt = -1L
        var fires = 0
        while (t <= 60 * minute) {
            detector.onHeartRate(t, 56)
            if (detector.tick(t)) {
                fires++
                if (firedAt < 0) firedAt = t
            }
            t += step
        }

        assertTrue("onset must be reported exactly once, got $fires", fires == 1)
        assertTrue("fired too early: ${firedAt / minute} min", firedAt > 20 * minute)
        assertTrue("fired too late: ${firedAt / minute} min", firedAt < 45 * minute)
    }

    @Test
    fun `does not fire when heart rate rises again`() {
        val detector = SleepDetector()
        detector.start(0L)

        var t = 0L
        while (t <= 10 * minute) {
            detector.onHeartRate(t, 62)
            detector.tick(t)
            t += step
        }
        // Settling -- conditions start to be met.
        while (t <= 15 * minute) {
            detector.onHeartRate(t, 56)
            detector.tick(t)
            t += step
        }
        // ... then the user wakes up.
        var fired = false
        while (t <= 30 * minute) {
            detector.onHeartRate(t, 80)
            if (detector.tick(t)) fired = true
            t += step
        }

        assertFalse("a heart-rate rise must cancel onset", fired)
    }

    /**
     * Regression: the settling decision uses a 3-minute median, which lags a
     * heart-rate rise. With the median on both sides the detector could pause
     * in the gap between "user woke up" and "median caught up". A single
     * sample must therefore block the pause.
     */
    @Test
    fun `a single high sample blocks the pause`() {
        val detector = SleepDetector()
        detector.start(0L)

        var t = 0L
        while (t <= 10 * minute) {
            detector.onHeartRate(t, 62)
            detector.tick(t)
            t += step
        }

        var fired = false
        while (t <= 16 * minute) {
            detector.onHeartRate(t, 56)
            if (t == 16 * minute) detector.onHeartRate(t, 85)
            if (detector.tick(t)) fired = true
            t += step
        }

        assertFalse("one awake sample must prevent the pause", fired)
    }

    @Test
    fun `does not fire when the user moves then settles`() {
        val detector = SleepDetector()
        detector.start(0L)

        var t = 0L
        while (t <= 10 * minute) {
            detector.onHeartRate(t, 62)
            detector.tick(t)
            t += step
        }
        var fired = false
        while (t <= 40 * minute) {
            detector.onHeartRate(t, 56)
            // rolling over every 90 seconds keeps motionOk false
            if (t % (90 * 1000L) == 0L) detector.onMotion(t, 3)
            if (detector.tick(t)) fired = true
            t += step
        }

        assertFalse("restless sleep is not onset", fired)
    }

    @Test
    fun `needs enough samples to learn the baseline`() {
        val detector = SleepDetector()
        detector.start(0L)
        detector.onHeartRate(0L, 62)
        detector.onHeartRate(minute, 62)

        var fired = false
        var t = 0L
        while (t <= 30 * minute) {
            if (detector.tick(t)) fired = true
            t += step
        }

        assertFalse("two samples are not a baseline", fired)
        assertNull(detector.status(t).baseline)
    }

    @Test
    fun `without a requirement it falls back to quiet time`() {
        val detector = SleepDetector(SleepDetector.Config(requireHeartRate = false))
        detector.start(0L)

        var fired = false
        var t = 0L
        while (t <= 25 * minute) {
            if (detector.tick(t)) fired = true
            t += step
        }

        assertTrue("quiet-only mode should fire", fired)
        assertTrue(detector.hasFired)
    }

    @Test
    fun `start resets a previous run`() {
        val detector = SleepDetector(SleepDetector.Config(requireHeartRate = false))
        detector.start(0L)
        var t = 0L
        while (t <= 20 * minute) {
            detector.tick(t)
            t += step
        }
        assertTrue(detector.hasFired)

        detector.start(100 * minute)
        assertFalse("a new session must not inherit the trigger", detector.hasFired)
        assertEquals(SleepDetector.Phase.AWAKE, detector.status(100 * minute).phase)
    }
}
