package dev.remiband.sleep

import android.content.ComponentName
import android.content.Context
import android.media.AudioManager
import android.media.session.MediaController
import android.media.session.MediaSessionManager
import android.media.session.PlaybackState
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.KeyEvent

/**
 * Pauses whatever is playing, without knowing which app it is.
 *
 * Two routes, in order of quality:
 *
 *  1. **MediaSession** -- ask the framework for the active sessions and call
 *     `pause()` on the one that is playing. Works for any well-behaved player
 *     (Bilibili, YouTube, Douyin, Spotify) and needs no per-app code.
 *     The catch: `getActiveSessions` is only available to a notification
 *     listener, so the user must grant notification access once.
 *
 *  2. **Media key** -- dispatch a KEYCODE_MEDIA_PAUSE. Broad support, but some
 *     players ignore it when the screen is off or they are in a preview.
 *
 * The fade runs before the pause because cutting sound abruptly at 2am is its
 * own way of waking someone up.
 */
class MediaGate(
    private val context: Context,
    private val log: (String) -> Unit,
) {

    private val handler = Handler(Looper.getMainLooper())

    /**
     * The missing-permission warning is emitted once, not once per tick.
     *
     * The service polls playback every 15 seconds; without this flag the log
     * fills with the same sentence and the one line that matters scrolls away.
     */
    private var warnedNoAccess = false

    fun notificationAccessGranted(): Boolean {
        val enabled = Settings.Secure.getString(
            context.contentResolver,
            "enabled_notification_listeners",
        ) ?: return false
        return enabled.split(':').any { it.contains(context.packageName) }
    }

    private fun sessionManager(): MediaSessionManager? =
        context.getSystemService(Context.MEDIA_SESSION_SERVICE) as? MediaSessionManager

    /** The controller that is currently playing, if any. */
    fun playingController(): MediaController? {
        val manager = sessionManager() ?: return null
        if (!notificationAccessGranted()) {
            if (!warnedNoAccess) {
                warnedNoAccess = true
                log("notification access is NOT granted: cannot see or pause any player")
                log("enable it at Settings > Apps > Special app access > Notification access")
            }
            return null
        }
        if (warnedNoAccess) {
            warnedNoAccess = false
            log("notification access granted: media control is live")
        }
        val component = ComponentName(context, MediaNotificationListener::class.java)
        val sessions = try {
            manager.getActiveSessions(component)
        } catch (e: SecurityException) {
            log("media sessions unavailable: ${e.message}")
            return null
        }
        return sessions.firstOrNull { it.playbackState?.state == PlaybackState.STATE_PLAYING }
    }

    fun isPlaying(): Boolean = playingController() != null

    /**
     * Ramp the music stream to zero over [totalMs], pause, then restore the
     * volume so the next video is not mysteriously silent.
     */
    fun pauseWithFade(totalMs: Long = 20_000L, onDone: (String?) -> Unit = {}) {
        val controller = playingController()

        if (controller == null) {
            log("no playing media session; falling back to a media key")
            pauseByKey()
            onDone(null)
            return
        }

        val app = controller.packageName
        val audio = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager
        val stream = AudioManager.STREAM_MUSIC
        val original = audio.getStreamVolume(stream)

        if (totalMs <= 0L) {
            pause(controller, audio, original, stream, app, onDone)
            return
        }

        val steps = 10
        val stepMs = (totalMs / steps).coerceAtLeast(150L)
        var remaining = steps

        log("fading out over ${totalMs / 1000}s before pausing $app")

        fun step() {
            remaining--
            val level = (original.toLong() * remaining / steps).toInt()
            try {
                audio.setStreamVolume(stream, level.coerceIn(0, original), 0)
            } catch (_: SecurityException) {
                // Volume control refused (Do Not Disturb). Not fatal: still pause.
            }
            if (remaining > 0) {
                handler.postDelayed({ step() }, stepMs)
            } else {
                pause(controller, audio, original, stream, app, onDone)
            }
        }
        step()
    }

    private fun pause(
        controller: MediaController,
        audio: AudioManager,
        original: Int,
        stream: Int,
        app: String,
        onDone: (String?) -> Unit,
    ) {
        try {
            controller.transportControls.pause()
            log("paused $app")
        } catch (e: Exception) {
            log("pause failed (${e.message}); trying a media key")
            pauseByKey()
        }
        handler.postDelayed({
            try {
                audio.setStreamVolume(stream, original, 0)
            } catch (_: SecurityException) {
            }
        }, 4_000L)
        onDone(app)
    }

    /** Last resort for players that ignore transport controls. */
    fun pauseByKey() {
        val audio = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager
        try {
            audio.dispatchMediaKeyEvent(
                KeyEvent(KeyEvent.ACTION_DOWN, KeyEvent.KEYCODE_MEDIA_PAUSE)
            )
            audio.dispatchMediaKeyEvent(
                KeyEvent(KeyEvent.ACTION_UP, KeyEvent.KEYCODE_MEDIA_PAUSE)
            )
            log("dispatched KEYCODE_MEDIA_PAUSE")
        } catch (e: Exception) {
            log("media key dispatch failed: ${e.message}")
        }
    }
}
