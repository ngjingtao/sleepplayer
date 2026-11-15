package dev.remiband.sleep

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import dev.remiband.probe.ProbeActivity

/**
 * One screen: arm the watchdog, and see what it thinks.
 *
 * The live "reason" line under the status is the important part -- it is the
 * detector explaining itself ("heart rate has not settled (64/62)") rather than
 * just sitting there. A sleep tool that silently decides nothing is worse than
 * no tool, because you cannot tell it apart from one that is broken.
 */
class SleepGuardActivity : Activity() {

    private lateinit var settings: Settings
    private val handler = Handler(Looper.getMainLooper())

    private lateinit var statusView: TextView
    private lateinit var reasonView: TextView
    private lateinit var accessView: TextView
    private lateinit var logView: TextView
    private lateinit var minutesField: EditText
    private lateinit var fadeField: EditText
    private lateinit var useBandBox: CheckBox
    private lateinit var addressField: EditText
    private lateinit var keyField: EditText
    private lateinit var hrOffsetField: EditText
    private lateinit var hrUuidField: EditText

    private val poll = object : Runnable {
        override fun run() {
            statusView.text = if (SleepWatchService.running) {
                "watching - ${SleepWatchService.status}"
            } else {
                "idle"
            }
            reasonView.text = SleepWatchService.detail.ifBlank {
                if (SleepWatchService.running) "waiting for the next tick" else "not running"
            }
            val lines = SleepWatchService.snapshotLog()
            logView.text = if (lines.isEmpty()) "(no log yet)" else lines.joinToString("\n")
            handler.postDelayed(this, 1_000L)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        settings = Settings(this)
        setContentView(buildUi())
        requestNotificationPermissionIfNeeded()
    }

    override fun onResume() {
        super.onResume()
        refreshAccess()
        handler.post(poll)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(poll)
    }

    // ------------------------------------------------------------------- UI

    private fun buildUi(): LinearLayout {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(18), dp(14), dp(10))
        }

        root.addView(TextView(this).apply {
            text = "Sleep guard"
            textSize = 22f
        })

        statusView = TextView(this).apply {
            text = "idle"
            textSize = 16f
            setPadding(0, dp(8), 0, 0)
        }
        root.addView(statusView)

        reasonView = TextView(this).apply {
            text = "not running"
            textSize = 13f
            setPadding(0, dp(2), 0, dp(10))
        }
        root.addView(reasonView)

        // playback budget + fade
        root.addView(row(
            labelled("playback min", edit(settings.minutes.toString(), number = true)
                .also { minutesField = it }),
            labelled("fade sec", edit(settings.fadeSeconds.toString(), number = true)
                .also { fadeField = it }),
        ))

        root.addView(row(
            button("Start watching") { startWatching() },
            button("Stop") { stopWatching() },
        ))

        root.addView(row(
            button("Grant notification access") { openNotificationAccess() },
            button("BLE probe") {
                startActivity(Intent(this, ProbeActivity::class.java))
            },
        ))

        accessView = TextView(this).apply {
            textSize = 12f
            setPadding(0, dp(4), 0, dp(8))
        }
        root.addView(accessView)

        // band section
        useBandBox = CheckBox(this).apply {
            text = "Use the band for sleep detection"
            isChecked = settings.useBand
        }
        root.addView(useBandBox)

        addressField = edit(settings.bandAddress, text = true).apply {
            hint = "band address (from the probe screen)"
        }
        root.addView(addressField)

        keyField = edit(settings.authKey, text = true).apply {
            hint = "16-byte auth key, hex (optional)"
        }
        root.addView(keyField)

        hrUuidField = edit(settings.heartRateUuid, text = true).apply {
            hint = "heart-rate characteristic UUID (default ff12)"
        }
        root.addView(hrUuidField)

        hrOffsetField = edit(settings.hrOffsetString(), number = true).apply {
            hint = "heart-rate bpm byte offset (-1 = log only)"
        }
        root.addView(hrOffsetField)

        root.addView(TextView(this).apply {
            text = "Band detection needs a band whose protocol we can speak. " +
                "On a Mi Band 10 that part is not cracked yet - use the probe " +
                "screen, and the timer still protects you meanwhile."
            textSize = 11f
            setPadding(0, dp(6), 0, dp(8))
        })

        // log
        logView = TextView(this).apply {
            text = "(no log yet)"
            textSize = 10f
            typeface = android.graphics.Typeface.MONOSPACE
        }
        root.addView(ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1f,
            )
            addView(logView)
        }, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f,
        ))

        root.addView(row(
            button("Copy log") { copyLog() },
            button("Clear log") { SleepWatchService.clearLog() },
        ))
        return root
    }

    private fun row(vararg children: android.view.View): LinearLayout =
        LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            children.forEach { addView(it) }
        }

    private fun labelled(caption: String, field: EditText): LinearLayout =
        LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            addView(TextView(this@SleepGuardActivity).apply {
                text = caption
                textSize = 11f
            })
            addView(field)
        }

    private fun edit(value: String, number: Boolean = false, text: Boolean = false): EditText =
        EditText(this).apply {
            setText(value)
            textSize = 13f
            if (number) inputType = InputType.TYPE_CLASS_NUMBER
            if (text) inputType = InputType.TYPE_CLASS_TEXT
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            )
        }

    private fun button(caption: String, onClick: () -> Unit): Button =
        Button(this).apply {
            text = caption
            textSize = 12f
            setOnClickListener { onClick() }
        }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    // -------------------------------------------------------------- actions

    private fun startWatching() {
        saveSettings()
        val intent = Intent(this, SleepWatchService::class.java).apply {
            action = SleepWatchService.ACTION_START
            putExtra(SleepWatchService.EXTRA_USE_BAND, useBandBox.isChecked)
            putExtra(SleepWatchService.EXTRA_MINUTES, settings.minutes)
            putExtra(SleepWatchService.EXTRA_FADE_SECONDS, settings.fadeSeconds)
        }
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
    }

    private fun stopWatching() {
        startService(
            Intent(this, SleepWatchService::class.java).apply {
                action = SleepWatchService.ACTION_STOP
            }
        )
    }

    private fun saveSettings() {
        settings.minutes = minutesField.text.toString().toIntOrNull() ?: settings.minutes
        settings.fadeSeconds = fadeField.text.toString().toIntOrNull() ?: settings.fadeSeconds
        settings.bandAddress = addressField.text.toString().trim()
        settings.authKey = keyField.text.toString().trim()
        settings.heartRateUuid = hrUuidField.text.toString().trim()
            .ifBlank { settings.heartRateUuid }
        settings.heartRateOffset = hrOffsetField.text.toString().toIntOrNull()
            ?: settings.heartRateOffset
        settings.useBand = useBandBox.isChecked
    }

    private fun openNotificationAccess() {
        try {
            startActivity(Intent(android.provider.Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
        } catch (e: Exception) {
            // Some OEM ROMs hide it; send the user to app settings instead.
            startActivity(Intent(android.provider.Settings.ACTION_SETTINGS))
        }
    }

    private fun refreshAccess() {
        val gate = MediaGate(this) { }
        val granted = gate.notificationAccessGranted()
        accessView.text = if (granted) {
            "notification access: granted - other apps' playback can be paused"
        } else {
            "notification access: NOT granted - only the media-key fallback will work"
        }
    }

    private fun copyLog() {
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
        clipboard.setPrimaryClip(
            android.content.ClipData.newPlainText(
                "remiband log",
                SleepWatchService.snapshotLog().joinToString("\n"),
            )
        )
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < 33) return
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
    }
}

private fun Settings.hrOffsetString(): String =
    if (heartRateOffset < 0) "" else heartRateOffset.toString()
