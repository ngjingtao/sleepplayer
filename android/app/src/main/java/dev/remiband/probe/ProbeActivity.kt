package dev.remiband.probe

import android.Manifest
import android.app.Activity
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import dev.remiband.ble.BleCentral
import dev.remiband.ble.gattStatusName
import dev.remiband.core.Hex
import dev.remiband.core.MibandProtocol
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The phone-side equivalent of `python3 -m remiband survey`: connect to
 * anything, print its attribute table, log every notification as hex, and
 * write arbitrary bytes.
 *
 * This makes no assumption about the protocol. On a band newer than the classic
 * one -- a Mi Band 10, for instance -- this screen is how you find out what the
 * device actually says, which is the input the protocol work needs.
 */
class ProbeActivity : Activity(), BleCentral.Listener {

    private lateinit var ble: BleCentral
    private lateinit var statusView: TextView
    private lateinit var logView: TextView
    private lateinit var deviceSpinner: Spinner
    private lateinit var hexField: EditText

    private val devices = ArrayList<BleCentral.Found>()
    private val logBuffer = StringBuilder()
    private var gatt: BluetoothGatt? = null
    private var pendingScan = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ble = BleCentral(this, this)
        setContentView(buildUi())
        log("probe ready - ${Build.MANUFACTURER} ${Build.MODEL}, API ${Build.VERSION.SDK_INT}")
    }

    override fun onDestroy() {
        ble.close()
        super.onDestroy()
    }

    // ------------------------------------------------------------------- UI

    private fun buildUi(): LinearLayout {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(16), dp(12), dp(8))
        }

        statusView = TextView(this).apply {
            text = "not connected"
            textSize = 15f
        }
        root.addView(statusView)

        root.addView(row(
            action("Scan") { withPermissions { scan() } },
            action("Connect") { withPermissions { connectSelected() } },
            action("Disconnect") { ble.disconnect(); gatt = null },
        ))

        deviceSpinner = Spinner(this)
        root.addView(deviceSpinner)

        hexField = EditText(this).apply {
            hint = "bytes to write, hex (e.g. a0 01 00 01 00)"
            textSize = 13f
            inputType = InputType.TYPE_CLASS_TEXT
        }
        root.addView(hexField)

        root.addView(row(
            action("Write raw") { sendRaw() },
            action("Clear log") { logBuffer.setLength(0); renderLog() },
        ))

        logView = TextView(this).apply {
            textSize = 10f
            typeface = android.graphics.Typeface.MONOSPACE
            text = "(no log yet)"
        }
        root.addView(
            ScrollView(this).apply { addView(logView) },
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f),
        )
        return root
    }

    private fun row(vararg children: android.view.View): LinearLayout =
        LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            children.forEach { addView(it) }
        }

    private fun action(caption: String, onClick: () -> Unit): Button =
        Button(this).apply {
            text = caption
            textSize = 12f
            setOnClickListener { onClick() }
        }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    // ------------------------------------------------------------ behaviour

    private fun requiredPermissions(): Array<String> =
        if (Build.VERSION.SDK_INT >= 31) {
            arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }

    private fun withPermissions(action: () -> Unit) {
        val missing = requiredPermissions().filter {
            checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) {
            action()
            return
        }
        requestPermissions(missing.toTypedArray(), 7)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
            if (pendingScan) {
                pendingScan = false
                scan()
            }
        } else {
            log("permissions denied - scanning needs Bluetooth permission")
        }
    }

    private fun scan() {
        pendingScan = true
        ble.scan(
            onFound = { found ->
                devices.clear()
                devices.addAll(found)
                renderDevices()
            },
            onFinished = { pendingScan = false },
        )
        log("scanning...")
    }

    private fun renderDevices() {
        val labels = devices.map { "${it.name}  (${it.address})  ${it.rssi}dBm" }
        deviceSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            labels,
        )
    }

    private fun connectSelected() {
        val index = deviceSpinner.selectedItemPosition
        if (index < 0 || index >= devices.size) {
            log("scan first, then pick a device")
            return
        }
        val target = devices[index]
        log("connecting to ${target.address}")
        ble.connect(target.address)
    }

    private fun sendRaw() {
        val g = gatt ?: run { log("not connected"); return }
        val bytes = Hex.decode(hexField.text.toString()) ?: run {
            log("not valid hex")
            return
        }
        val target = ble.characteristic(g, MibandProtocol.CONTROL_POINT)
            ?: firstWritable(g)
            ?: run { log("no writable characteristic found"); return }

        log("-> ${Hex.encode(bytes)}  (${MibandProtocol.uuidLabel(target.uuid)})")
        ble.write(target, bytes, false)
    }

    private fun firstWritable(g: BluetoothGatt): BluetoothGattCharacteristic? {
        for (service in g.services) {
            for (c in service.characteristics) {
                val p = c.properties
                if (p and BluetoothGattCharacteristic.PROPERTY_WRITE != 0 ||
                    p and BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE != 0
                ) {
                    return c
                }
            }
        }
        return null
    }

    // ------------------------------------------------------- BleCentral.Listener

    override fun onLog(line: String) = log(line)

    override fun onState(text: String) {
        statusView.text = text
        log(text)
    }

    override fun onConnected(gatt: BluetoothGatt) {
        this.gatt = gatt
        statusView.text = "connected"
    }

    override fun onDisconnected(status: Int) {
        gatt = null
        statusView.text = "disconnected"
    }

    override fun onError(stage: String, status: Int) {
        log("$stage failed: ${gattStatusName(status)}")
    }

    override fun onServicesReady(gatt: BluetoothGatt) {
        this.gatt = gatt
        log("--- attribute table ---")
        for (service in gatt.services) {
            log("${MibandProtocol.uuidLabel(service.uuid)}")
            for (c in service.characteristics) {
                log(
                    "   h=0x%04x %-42s [%s]".format(
                        c.instanceId,
                        MibandProtocol.uuidLabel(c.uuid),
                        properties(c),
                    )
                )
            }
        }
        log("--- end of table ---")

        val notifyCapable = gatt.services
            .flatMap { it.characteristics }
            .filter {
                it.properties and BluetoothGattCharacteristic.PROPERTY_NOTIFY != 0 ||
                    it.properties and BluetoothGattCharacteristic.PROPERTY_INDICATE != 0
            }
        notifyCapable.forEach { ble.subscribe(it) }
        log("subscribed to ${notifyCapable.size} notify characteristics")
    }

    override fun onNotify(characteristic: BluetoothGattCharacteristic, value: ByteArray) {
        val label = MibandProtocol.uuidLabel(characteristic.uuid)
        val frame = MibandProtocol.decodeFrame(value, fromBand = true)
        val suffix = when {
            frame == null -> "(unframed)"
            frame.kind == MibandProtocol.Kind.RESPONSE ->
                "(a0 response type=0x%02x status=0x%02x)".format(frame.cmd, frame.status)
            else -> ""
        }
        log("<- $label  ${Hex.encode(value)}  $suffix")
    }

    private fun properties(c: BluetoothGattCharacteristic): String {
        val p = c.properties
        val parts = ArrayList<String>()
        if (p and BluetoothGattCharacteristic.PROPERTY_READ != 0) parts.add("read")
        if (p and BluetoothGattCharacteristic.PROPERTY_WRITE != 0) parts.add("write")
        if (p and BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE != 0) parts.add("write-nr")
        if (p and BluetoothGattCharacteristic.PROPERTY_NOTIFY != 0) parts.add("notify")
        if (p and BluetoothGattCharacteristic.PROPERTY_INDICATE != 0) parts.add("indicate")
        return parts.joinToString(",")
    }

    // ------------------------------------------------------------------ log

    private fun log(line: String) {
        val stamp = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
        logBuffer.append(stamp).append("  ").append(line).append('\n')
        renderLog()
    }

    private fun renderLog() {
        logView.text = if (logBuffer.isEmpty()) "(no log yet)" else logBuffer.toString()
    }
}
