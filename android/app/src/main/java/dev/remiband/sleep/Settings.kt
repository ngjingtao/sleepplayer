package dev.remiband.sleep

import android.content.Context

/**
 * Tiny SharedPreferences wrapper. One place for every persisted value, so the
 * activity and the service cannot disagree about a default.
 */
class Settings(context: Context) {

    private val prefs = context.getSharedPreferences("remiband", Context.MODE_PRIVATE)

    /** Minutes of *actual playback* before the timer backstop fires. */
    var minutes: Int
        get() = prefs.getInt("minutes", 45)
        set(value) = prefs.edit().putInt("minutes", value).apply()

    /** Fade-out length in seconds. 0 disables the fade. */
    var fadeSeconds: Int
        get() = prefs.getInt("fade", 20)
        set(value) = prefs.edit().putInt("fade", value).apply()

    /** MAC/address of the band, as shown by the probe screen. */
    var bandAddress: String
        get() = prefs.getString("bandAddress", "") ?: ""
        set(value) = prefs.edit().putString("bandAddress", value).apply()

    /** 16-byte auth key as hex, or empty. */
    var authKey: String
        get() = prefs.getString("authKey", "") ?: ""
        set(value) = prefs.edit().putString("authKey", value).apply()

    /**
     * Which characteristic carries heart rate.
     *
     * Defaults to the classic `ff12`. On a newer band it will not exist, and
     * the service switches to learn mode: subscribe to everything, log every
     * notification, and let the capture or the log tell you the real UUID.
     */
    var heartRateUuid: String
        get() = prefs.getString("heartRateUuid", "0000ff12-0000-1000-8000-00805f9b34fb")
            ?: "0000ff12-0000-1000-8000-00805f9b34fb"
        set(value) = prefs.edit().putString("heartRateUuid", value).apply()

    /**
     * Which byte of a heart-rate notification carries the bpm, or -1 when
     * unknown.
     *
     * This is a setting rather than a constant on purpose: the frame layout of
     * the heart-rate characteristic is not verified for a Mi Band 10, and
     * silently reading the wrong byte would feed the detector plausible-looking
     * noise. Unknown means "log it and let me look", not "guess".
     */
    var heartRateOffset: Int
        get() = prefs.getInt("heartRateOffset", -1)
        set(value) = prefs.edit().putInt("heartRateOffset", value).apply()

    var useBand: Boolean
        get() = prefs.getBoolean("useBand", false)
        set(value) = prefs.edit().putBoolean("useBand", value).apply()
}
