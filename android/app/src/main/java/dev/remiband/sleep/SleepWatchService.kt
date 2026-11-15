package dev.remiband.sleep

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import dev.remiband.ble.BleCentral
import dev.remiband.ble.gattStatusName
import dev.remiband.core.AuthSession
import dev.remiband.core.Hex
import dev.remiband.core.MibandProtocol
import java.text.SimpleDateFormat
import java.util.UUID
import java.util.Date
import java.util.Locale

/**
 * Foreground service that watches a video session and stops it when the user
 * falls asleep.
 *
 * Two arming modes, and they compose:
 *
 *  * **timer** -- counts only time when media is *actually playing*, so a
 *    paused video does not consume the budget. This works today, on any phone,
 *    with no band.
 *  * **band** -- feeds heart rate and wrist motion into [SleepDetector] and
 *    pauses when onset is confirmed. This is the mode that needs a band whose
 *    protocol we can speak; see docs in android/README.md.
 *
 * The timer is not a fallback that pretends to be smart: it is a backstop that
 * guarantees the video does not play until morning even when the band path is
 * unavailable, which is the actual harm being prevented.
 */
class SleepWatchService : Service(), BleCentral.Listener {

    companion object {
        const val ACTION_START = "dev.remiband.sleep.action.START"
        const val ACTION_STOP = "dev.remiband.sleep.action.STOP"
        const val EXTRA_USE_BAND = "useBand"
        const val EXTRA_MINUTES = "minutes"
        const val EXTRA_FADE_SECONDS = "fadeSeconds"

        private const val CHANNEL_ID = "sleep_guard"
        private const val NOTIFICATION_ID = 42
        private const val TICK_MS = 15_000L

        /** Read by the activity; the service owns the truth. */
        @Volatile
        var status: String = "idle"

        @Volatile
        var detail: String = ""

        @Volatile
        var running: Boolean = false

        private val recentLog = ArrayDeque<String>()

        @Synchronized
        fun record(line: String) {
            recentLog.addLast(line)
            while (recentLog.size > 300) recentLog.removeFirst()
        }

        @Synchronized
        fun snapshotLog(): List<String> = recentLog.toList()

        @Synchronized
        fun clearLog() = recentLog.clear()
    }

    private lateinit var handler: Handler
    private lateinit var settings: Settings
    private lateinit var media: MediaGate

    private var detector: SleepDetector? = null
    private var ble: BleCentral? = null
    private var auth: AuthSession? = null
    private var authChar: BluetoothGattCharacteristic? = null
    private var hrChar: BluetoothGattCharacteristic? = null
    private var hrUuid: UUID? = null
    private var learnMode = false
    private var wakeLock: PowerManager.WakeLock? = null

    private var playMs = 0L
    private var targetMs = 45 * 60_000L
    private var fadeMs = 20_000L
    private var triggered = false
    private var blind = false

    private val tick = object : Runnable {
        override fun run() {
            if (!running) return
            val now = SystemClock.elapsedRealtime()

            // Without notification access isPlaying() is always false, which
            // used to mean the timer never advanced at all -- the app looked
            // broken rather than degraded. Count wall time instead, and let the
            // media key do the pausing.
            val canSeeSessions = media.notificationAccessGranted()
            if (canSeeSessions && blind) {
                blind = false
                log("notification access appeared; back to counting real playback")
            }
            val playing = if (canSeeSessions) media.isPlaying() else true
            if (!canSeeSessions && !blind) {
                blind = true
                log("no notification access: counting wall time, will pause with a media key")
            }
            if (playing) playMs += TICK_MS

            val d = detector
            if (d != null) {
                if (d.tick(now)) {
                    trigger("band: ${d.status(now).reason}")
                } else {
                    detail = d.status(now).reason
                }
            }

            if (!triggered && playMs >= targetMs) {
                trigger("played ${playMs / 60_000} min")
            }

            updateNotification()
            handler.postDelayed(this, TICK_MS)
        }
    }

    override fun onCreate() {
        super.onCreate()
        handler = Handler(Looper.getMainLooper())
        settings = Settings(this)
        media = MediaGate(this) { line -> log(line) }
        createChannel()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            return START_NOT_STICKY
        }
        val useBand = intent?.getBooleanExtra(EXTRA_USE_BAND, settings.useBand) ?: settings.useBand
        val minutes = intent?.getIntExtra(EXTRA_MINUTES, settings.minutes) ?: settings.minutes
        val fadeSeconds =
            intent?.getIntExtra(EXTRA_FADE_SECONDS, settings.fadeSeconds) ?: settings.fadeSeconds
        start(useBand, minutes, fadeSeconds)
        return START_STICKY
    }

    private fun start(useBand: Boolean, minutes: Int, fadeSeconds: Int) {
        playMs = 0L
        triggered = false
        running = true
        targetMs = minutes.coerceAtLeast(1) * 60_000L
        fadeMs = fadeSeconds.coerceAtLeast(0) * 1000L
        status = "watching"
        detail = if (useBand) "band mode" else "timer mode"

        startForeground(NOTIFICATION_ID, buildNotification())
        acquireWakeLock()

        if (useBand) startBand()

        handler.removeCallbacks(tick)
        handler.postDelayed(tick, TICK_MS)
        log("started: ${targetMs / 60_000} min of playback, fade ${fadeMs / 1000}s, band=$useBand")
    }

    // ------------------------------------------------------------ the trigger

    private fun trigger(why: String) {
        if (triggered) return
        triggered = true
        status = "pausing"
        detail = why
        updateNotification()
        log("TRIGGER: $why")

        media.pauseWithFade(fadeMs) { app ->
            status = if (app != null) "paused" else "paused (media key)"
            detail = app ?: why
            updateNotification()
            handler.postDelayed({ shutdown() }, 6_000L)
        }
    }

    private fun shutdown() {
        if (!running && ble == null) {
            stopSelf()
            return
        }
        running = false
        handler.removeCallbacks(tick)
        ble?.disconnect()
        ble = null
        detector?.stop()
        detector = null
        auth = null
        hrUuid = null
        hrChar = null
        learnMode = false
        releaseWakeLock()
        status = "idle"
        detail = ""
        log("stopped")
        stopForegroundCompat()
        stopSelf()
    }

    // ----------------------------------------------------------------- band

    private fun startBand() {
        val address = settings.bandAddress
        if (address.isBlank()) {
            log("band mode requested but no address saved -- timer still active")
            detail = "band: no address saved (timer only)"
            return
        }
        val d = SleepDetector()
        d.start(SystemClock.elapsedRealtime())
        detector = d

        val central = BleCentral(this, this)
        ble = central
        central.connect(address)
    }

    override fun onLog(line: String) = log(line)

    override fun onState(text: String) {
        detail = text
        log(text)
    }

    override fun onConnected(gatt: BluetoothGatt) {
        log("band connected")
    }

    override fun onDisconnected(status: Int) {
        log("band disconnected")
        detail = "band disconnected (timer still active)"
    }

    override fun onError(stage: String, status: Int) {
        log("$stage failed: ${gattStatusName(status)}")
    }

    override fun onServicesReady(gatt: BluetoothGatt) {
        log("discovered ${gatt.services.size} services")

        val configured = runCatching { UUID.fromString(settings.heartRateUuid.trim()) }.getOrNull()
        val candidates = listOfNotNull(
            configured,
            MibandProtocol.HR_MEASUREMENT,   // standard, self-describing
            MibandProtocol.HEART_RATE_DATA,  // classic Mi Band ff12
        )
        val hr = candidates.firstNotNullOfOrNull { ble?.characteristic(gatt, it) }

        if (hr != null) {
            hrChar = hr
            hrUuid = hr.uuid
            ble?.subscribe(hr)
            log("subscribed to heart rate on ${MibandProtocol.uuidLabel(hr.uuid)}")
            if (hr.uuid == MibandProtocol.HR_MEASUREMENT) {
                log("standard heart-rate format: no byte offset needed")
            } else {
                log("vendor characteristic: byte offset must be configured")
            }
        } else {
            log("no heart-rate characteristic found (tried $candidates)")
            detail = "band: learn mode (no heart-rate characteristic)"
            subscribeAllNotify(gatt)
        }

        val authCharacteristic = ble?.characteristic(gatt, MibandProtocol.AUTH_UUID)
        val key = Hex.decode(settings.authKey)
        when {
            authCharacteristic != null && key != null && key.size == 16 -> {
                authChar = authCharacteristic
                auth = AuthSession(key)
                log("auth: starting handshake")
                pushAuthStep()
            }
            authCharacteristic != null ->
                log("auth characteristic present but no 16-byte key saved")
            else ->
                log("no Mi Band auth characteristic on this device")
        }
    }

    override fun onNotify(characteristic: BluetoothGattCharacteristic, value: ByteArray) {
        if (characteristic.uuid == MibandProtocol.AUTH_UUID) {
            val session = auth ?: return
            session.onNotify(value)
            log("auth <- ${Hex.encode(value)}")
            when (session.state) {
                AuthSession.State.AUTHENTICATED -> log("AUTHENTICATED")
                AuthSession.State.FAILED -> log("AUTH FAILED -- key is wrong")
                else -> pushAuthStep()
            }
            return
        }

        val label = MibandProtocol.uuidLabel(characteristic.uuid)
        val isHeartRate = characteristic.uuid == hrUuid
        log("$label <- ${Hex.encode(value)}${if (isHeartRate) "   <-- heart rate" else ""}")

        if (isHeartRate) {
            feedHeartRate(value)
        } else if (settings.heartRateOffset >= 0 && learnMode) {
            // Learn mode: show what the configured offset *would* yield here, so
            // you can tell the step counter apart from the heart rate without
            // feeding garbage into the detector.
            val offset = settings.heartRateOffset
            if (offset < value.size) {
                log("   (byte@$offset here would be ${value[offset].toInt() and 0xFF})")
            }
        }
    }

    private fun subscribeAllNotify(gatt: BluetoothGatt) {
        val candidates = gatt.services
            .flatMap { it.characteristics }
            .filter { c ->
                c.properties and BluetoothGattCharacteristic.PROPERTY_NOTIFY != 0 ||
                    c.properties and BluetoothGattCharacteristic.PROPERTY_INDICATE != 0
            }
        if (candidates.isEmpty()) {
            log("this device exposes nothing notify-capable")
            return
        }
        candidates.forEach { ble?.subscribe(it) }
        learnMode = true
        log("learn mode: subscribed to ${candidates.size} notifications")
        log("do something on the band, then find the UUID whose payload tracks your pulse")
    }

    private fun feedHeartRate(value: ByteArray) {
        if (hrUuid == MibandProtocol.HR_MEASUREMENT) {
            val bpm = MibandProtocol.decodeHeartRateMeasurement(value)
            if (bpm == null) {
                log("not a parsable standard heart-rate measurement")
                return
            }
            note(bpm)
            return
        }

        val offset = settings.heartRateOffset
        if (offset < 0) {
            log("heart-rate offset is -1: log only, not feeding the detector")
            return
        }
        if (offset >= value.size) return
        val bpm = value[offset].toInt() and 0xFF
        if (bpm in 25..250) {
            note(bpm)
        } else {
            log("byte@$offset = $bpm is not a plausible bpm; offset likely wrong")
        }
    }

    private fun note(bpm: Int) {
        detail = "HR $bpm bpm"
        detector?.onHeartRate(SystemClock.elapsedRealtime(), bpm)
    }

    private fun pushAuthStep() {
        val session = auth ?: return
        val target = authChar ?: return
        val next = session.nextWrite() ?: return
        session.onWrite(next)
        log("auth -> ${Hex.encode(next)}")
        ble?.write(target, next, true)
    }

    // ----------------------------------------------------------- notification

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Sleep guard",
                NotificationManager.IMPORTANCE_LOW,
            )
            channel.description = "Stops playback when you fall asleep"
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, SleepGuardActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, SleepWatchService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val builder = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("Sleep guard: $status")
            .setContentText(detail.ifBlank { "watching playback" })
            .setSmallIcon(android.R.drawable.ic_lock_idle_alarm)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(
                Notification.Action.Builder(null, "Stop", stop).build()
            )
            .build()
    }

    private fun updateNotification() {
        try {
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.notify(NOTIFICATION_ID, buildNotification())
        } catch (_: Exception) {
            // Notification permission revoked mid-run; the service still works.
        }
    }

    @Suppress("DEPRECATION")
    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= 24) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            stopForeground(true)
        }
    }

    // -------------------------------------------------------------- plumbing

    private fun acquireWakeLock() {
        if (wakeLock != null) return
        val power = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "remiband:sleepwatch").apply {
            acquire(8 * 60 * 60 * 1000L)
        }
        log("wake lock acquired")
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }

    private fun log(line: String) {
        val stamp = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        record("$stamp  $line")
    }

    override fun onDestroy() {
        running = false
        handler.removeCallbacks(tick)
        ble?.disconnect()
        releaseWakeLock()
        super.onDestroy()
    }
}
