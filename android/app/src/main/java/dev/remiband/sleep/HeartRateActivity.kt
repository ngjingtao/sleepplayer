package dev.remiband.sleep

import android.Manifest
import android.app.Activity
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import dev.remiband.ble.BleCentral
import dev.remiband.ble.gattStatusName
import dev.remiband.core.Hex
import dev.remiband.core.MibandProtocol
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

/**
 * A page whose only job is: show my heart rate.
 *
 * The service reads heart rate too, but its output is a log inside a
 * background service -- fine for debugging an algorithm, useless for answering
 * "is this thing actually reading my pulse". This screen makes the number the
 * biggest thing on the display.
 *
 * It resolves the source in priority order (configured UUID, standard 0x2A37,
 * classic ff12). When none of those exist it subscribes to every notification
 * and prints, for each incoming packet, which byte positions currently hold a
 * plausible pulse -- so a vendor-specific format can be identified by eye
 * instead of by guesswork.
 */
class HeartRateActivity : Activity(), BleCentral.Listener {

    private companion object {
        const val BLE_CODE = 41
    }

    private lateinit var ble: BleCentral
    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    private lateinit var settings: Settings

    private lateinit var statusView: TextView
    private lateinit var bpmView: TextView
    private lateinit var sourceView: TextView
    private lateinit var rawView: TextView
    private lateinit var logView: TextView
    private lateinit var addressField: EditText
    private lateinit var offsetField: EditText

    private var pendingBleAction: (() -> Unit)? = null
    private var hrUuid: UUID? = null
    private val lastLogged = HashMap<UUID, Long>()
    private val logBuffer = StringBuilder()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        settings = Settings(this)
        ble = BleCentral(this, this)
        setContentView(buildUi())
        appendLog("ready - tap Scan, pick the band, then Connect")
        if (settings.bandAddress.isNotBlank()) {
            addressField.setText(settings.bandAddress)
        }
    }

    override fun onDestroy() {
        ble.close()
        super.onDestroy()
    }

    // ------------------------------------------------------------------- UI

    private fun buildUi(): LinearLayout {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(16), dp(14), dp(8))
        }

        root.addView(TextView(this).apply {
            text = "Heart rate"
            textSize = 20f
        })

        statusView = TextView(this).apply {
            text = "disconnected"
            textSize = 13f
            setPadding(0, dp(6), 0, 0)
        }
        root.addView(statusView)

        bpmView = TextView(this).apply {
            text = "--"
            textSize = 64f
            setPadding(0, dp(8), 0, 0)
        }
        root.addView(bpmView)

        sourceView = TextView(this).apply {
            text = "source: (not connected)"
            textSize = 12f
        }
        root.addView(sourceView)

        rawView = TextView(this).apply {
            text = ""
            textSize = 11f
            typeface = android.graphics.Typeface.MONOSPACE
        }
        root.addView(rawView)

        addressField = EditText(this).apply {
            hint = "band address"
            textSize = 12f
            inputType = InputType.TYPE_CLASS_TEXT
        }
        root.addView(addressField)

        root.addView(row(
            button("Scan") { scanForBand() },
            button("Connect") { connect() },
            button("Disconnect") { ble.disconnect() },
        ))

        offsetField = EditText(this).apply {
            hint = "bpm byte offset"
            textSize = 12f
            inputType = InputType.TYPE_CLASS_NUMBER
            setText(if (settings.heartRateOffset >= 0) settings.heartRateOffset.toString() else "")
        }
        root.addView(row(offsetField, button("Save offset") {
            settings.heartRateOffset = offsetField.text.toString().toIntOrNull() ?: -1
            appendLog("offset saved: ${settings.heartRateOffset}")
        }))

        logView = TextView(this).apply {
            textSize = 10f
            typeface = android.graphics.Typeface.MONOSPACE
            text = "(no log yet)"
        }
        root.addView(
            ScrollView(this).apply { addView(logView) },
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f),
        )

        root.addView(row(
            button("Clear log") { logBuffer.setLength(0); renderLog() },
            button("Copy log") { copyLog() },
        ))
        return root
    }

    private fun row(vararg children: android.view.View): LinearLayout =
        LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            children.forEach { addView(it) }
        }

    private fun button(caption: String, onClick: () -> Unit): Button =
        Button(this).apply {
            text = caption
            textSize = 12f
            setOnClickListener { onClick() }
        }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    // ------------------------------------------------------------ connecting

    private fun permissions(): Array<String> =
        if (Build.VERSION.SDK_INT >= 31) {
            arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }

    private fun withPermission(action: () -> Unit) {
        val missing = permissions().filter {
            checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) {
            action()
            return
        }
        pendingBleAction = action
        requestPermissions(missing.toTypedArray(), BLE_CODE)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != BLE_CODE) return
        val granted = grantResults.isNotEmpty() &&
            grantResults.all { it == PackageManager.PERMISSION_GRANTED }
        val action = pendingBleAction
        pendingBleAction = null
        if (granted) action?.invoke() else appendLog("Bluetooth permission denied")
    }

    private fun scanForBand() {
        withPermission {
            val adapter = (getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
            if (adapter == null || !adapter.isEnabled) {
                appendLog("Bluetooth is off")
                return@withPermission
            }
            val scanner = adapter.bluetoothLeScanner ?: return@withPermission
            statusView.text = "scanning 10s..."
            val found = LinkedHashMap<String, String>()
            val callback = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    val name = try {
                        result.device.name ?: result.scanRecord?.deviceName
                    } catch (e: SecurityException) {
                        null
                    } ?: "(unnamed)"
                    found[result.device.address] = name
                }
            }
            scanner.startScan(callback)
            handler.postDelayed({
                try {
                    scanner.stopScan(callback)
                } catch (_: Exception) {
                }
                statusView.text = "disconnected"
                showChooser(found)
            }, 10_000L)
        }
    }

    private fun showChooser(found: Map<String, String>) {
        if (found.isEmpty()) {
            appendLog("no devices found")
            return
        }
        val entries = found.entries.toList()
        val labels = entries.map { "${it.value}\n${it.key}" }.toTypedArray()
        android.app.AlertDialog.Builder(this)
            .setTitle("Pick your band")
            .setItems(labels) { _, which ->
                val (address, name) = entries[which]
                addressField.setText(address)
                settings.bandAddress = address
                appendLog("selected $name ($address)")
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun connect() {
        withPermission {
            val address = addressField.text.toString().trim()
            if (address.isBlank()) {
                appendLog("scan and pick a band first")
                return@withPermission
            }
            settings.bandAddress = address
            bpmView.text = "--"
            sourceView.text = "source: connecting..."
            appendLog("connecting to $address")
            ble.connect(address)
        }
    }

    // ------------------------------------------------------- BleCentral.Listener

    override fun onLog(line: String) = appendLog(line)

    override fun onState(text: String) {
        statusView.text = text
    }

    override fun onConnected(gatt: BluetoothGatt) {
        statusView.text = "connected"
        appendLog("connected")
    }

    override fun onDisconnected(status: Int) {
        statusView.text = "disconnected"
        bpmView.text = "--"
        hrUuid = null
    }

    override fun onError(stage: String, status: Int) {
        appendLog("$stage failed: ${gattStatusName(status)}")
    }

    override fun onServicesReady(gatt: BluetoothGatt) {
        appendLog("discovered ${gatt.services.size} services")

        val configured = runCatching { UUID.fromString(settings.heartRateUuid.trim()) }.getOrNull()
        val candidates = listOfNotNull(
            configured,
            MibandProtocol.HR_MEASUREMENT,
            MibandProtocol.HEART_RATE_DATA,
        )
        val found = candidates.firstNotNullOfOrNull { ble.characteristic(gatt, it) }

        if (found != null) {
            hrUuid = found.uuid
            sourceView.text = "source: ${MibandProtocol.uuidLabel(found.uuid)}"
            ble.subscribe(found)
            appendLog("subscribed to ${MibandProtocol.uuidLabel(found.uuid)}")
            if (found.uuid != MibandProtocol.HR_MEASUREMENT) {
                appendLog("vendor format: set the bpm byte offset from the raw bytes below")
            }
        } else {
            sourceView.text = "source: none found - learn mode"
            appendLog("no heart-rate characteristic (tried $candidates)")
            val notifyCapable = gatt.services
                .flatMap { it.characteristics }
                .filter {
                    it.properties and BluetoothGattCharacteristic.PROPERTY_NOTIFY != 0 ||
                        it.properties and BluetoothGattCharacteristic.PROPERTY_INDICATE != 0
                }
            notifyCapable.forEach { ble.subscribe(it) }
            appendLog("subscribed to ${notifyCapable.size} notifications; watch for a byte that tracks your pulse")
        }
    }

    override fun onNotify(characteristic: BluetoothGattCharacteristic, value: ByteArray) {
        val label = MibandProtocol.uuidLabel(characteristic.uuid)
        val isSource = characteristic.uuid == hrUuid

        if (isSource) {
            val bpm = if (characteristic.uuid == MibandProtocol.HR_MEASUREMENT) {
                MibandProtocol.decodeHeartRateMeasurement(value)
            } else {
                val offset = settings.heartRateOffset
                if (offset in value.indices) value[offset].toInt() and 0xFF else null
            }
            rawView.text = "${Hex.encode(value)}\n${label}"
            if (bpm != null && bpm in 25..250) {
                bpmView.text = bpm.toString()
                appendLog("$label <- ${Hex.encode(value)}  => $bpm bpm")
            } else {
                bpmView.text = "--"
                appendLog("$label <- ${Hex.encode(value)}  (no plausible bpm)")
            }
            return
        }

        // Learn mode: throttle to one line per second per characteristic, and
        // surface which byte positions look like a pulse right now.
        val now = System.currentTimeMillis()
        val previous = lastLogged[characteristic.uuid] ?: 0L
        if (now - previous < 1_000L) return
        lastLogged[characteristic.uuid] = now

        val candidates = buildString {
            for (i in 0 until minOf(value.size, 8)) {
                val v = value[i].toInt() and 0xFF
                if (v in 40..200) append(" b$i=$v")
            }
        }
        appendLog("$label <- ${Hex.encode(value)}${if (candidates.isNotEmpty()) "  cand:$candidates" else ""}")
    }

    // ------------------------------------------------------------------ log

    private fun appendLog(line: String) {
        val stamp = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
        logBuffer.append(stamp).append("  ").append(line).append('\n')
        if (logBuffer.length > 40_000) logBuffer.delete(0, 20_000)
        renderLog()
    }

    private fun renderLog() {
        logView.text = if (logBuffer.isEmpty()) "(no log yet)" else logBuffer.toString()
    }

    private fun copyLog() {
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
        clipboard.setPrimaryClip(
            android.content.ClipData.newPlainText("heart rate log", logBuffer.toString())
        )
    }
}
