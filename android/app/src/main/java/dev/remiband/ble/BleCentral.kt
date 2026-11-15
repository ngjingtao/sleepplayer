package dev.remiband.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import dev.remiband.core.MibandProtocol

/**
 * Scan / connect / GATT plumbing, with one important discipline: **every GATT
 * operation goes through a serial queue spaced [OP_GAP_MS] apart.**
 *
 * Android's GATT stack allows one outstanding operation per connection. Firing
 * `discoverServices`, five `writeDescriptor`s and a `writeCharacteristic` back
 * to back is the classic way to get `status 133` and lose the connection, and
 * the failure looks like a protocol error rather than a framework one. The
 * spacing is crude but reliable, which is what a diagnostic tool wants.
 */
@SuppressLint("MissingPermission")
class BleCentral(
    private val context: Context,
    private val listener: Listener,
) {

    interface Listener {
        fun onLog(line: String)
        fun onState(text: String)
        fun onConnected(gatt: BluetoothGatt)
        fun onDisconnected(status: Int)
        fun onServicesReady(gatt: BluetoothGatt)
        fun onNotify(characteristic: BluetoothGattCharacteristic, value: ByteArray)
        fun onError(stage: String, status: Int)
    }

    data class Found(val name: String, val address: String, val rssi: Int)

    private val handler = Handler(Looper.getMainLooper())
    private val queue = ArrayDeque<() -> Unit>()
    private var pumping = false
    private var gatt: BluetoothGatt? = null
    private var scanCallback: ScanCallback? = null
    private var lastAddress: String? = null
    private var retryBudget = 1

    companion object {
        private const val OP_GAP_MS = 150L
        private const val SCAN_MS = 12_000L
        private const val MTU_REQUEST = 247
    }

    // ------------------------------------------------------------------ scan

    fun scan(onFound: (List<Found>) -> Unit, onFinished: () -> Unit) {
        val adapter = adapter()
        if (adapter == null) {
            listener.onLog("this device has no Bluetooth adapter")
            onFinished()
            return
        }
        if (!adapter.isEnabled) {
            listener.onLog("Bluetooth is turned off")
            onFinished()
            return
        }
        val scanner = adapter.bluetoothLeScanner
        if (scanner == null) {
            listener.onLog("LE scanning unavailable (adapter has no LE support?)")
            onFinished()
            return
        }

        stopScan()
        val found = LinkedHashMap<String, Found>()

        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val name = try {
                    result.device.name ?: result.scanRecord?.deviceName
                } catch (e: SecurityException) {
                    null
                } ?: "(unnamed)"
                found[result.device.address] = Found(name, result.device.address, result.rssi)
                onFound(found.values.toList())
            }

            override fun onScanFailed(errorCode: Int) {
                listener.onLog("scan failed, code $errorCode")
                onFinished()
            }
        }

        scanCallback = callback
        try {
            scanner.startScan(callback)
        } catch (e: SecurityException) {
            listener.onLog("scan permission denied")
            onFinished()
            return
        }
        listener.onState("scanning...")

        handler.postDelayed({
            stopScan()
            listener.onState("scan finished")
            onFinished()
        }, SCAN_MS)
    }

    fun stopScan() {
        val callback = scanCallback ?: return
        scanCallback = null
        try {
            adapter()?.bluetoothLeScanner?.stopScan(callback)
        } catch (_: Exception) {
            // Adapter went away; nothing useful to do.
        }
    }

    // --------------------------------------------------------------- connect

    fun connect(address: String) {
        val adapter = adapter()
        if (adapter == null) {
            listener.onLog("this device has no Bluetooth adapter")
            return
        }
        val device: BluetoothDevice = try {
            adapter.getRemoteDevice(address)
        } catch (e: IllegalArgumentException) {
            listener.onLog("not a valid address: $address")
            return
        }

        close()
        lastAddress = address
        listener.onState("connecting to $address")
        val newGatt = try {
            device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
        } catch (e: SecurityException) {
            listener.onLog("connect permission denied")
            return
        }
        gatt = newGatt
    }

    fun disconnect() {
        val current = gatt
        gatt = null
        queue.clear()
        if (current != null) {
            try {
                current.disconnect()
                current.close()
            } catch (_: Exception) {
            }
        }
    }

    fun close() = disconnect()

    val isConnected: Boolean get() = gatt != null

    // -------------------------------------------------------------- gatt ops

    fun write(characteristic: BluetoothGattCharacteristic, value: ByteArray, withResponse: Boolean) {
        enqueue {
            val g = gatt ?: return@enqueue
            val type = if (withResponse) {
                BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            } else {
                BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
            }
            try {
                writeCompat(g, characteristic, value, type)
            } catch (e: SecurityException) {
                listener.onLog("write denied by permission")
            }
        }
    }

    fun subscribe(characteristic: BluetoothGattCharacteristic) {
        enqueue {
            val g = gatt ?: return@enqueue
            g.setCharacteristicNotification(characteristic, true)
            val cccd = characteristic.getDescriptor(MibandProtocol.CCCD_UUID)
            if (cccd == null) {
                listener.onLog("no CCCD on ${MibandProtocol.uuidLabel(characteristic.uuid)}")
                return@enqueue
            }
            val enablesNotify =
                (characteristic.properties and BluetoothGattCharacteristic.PROPERTY_NOTIFY) != 0
            val value = if (enablesNotify) {
                BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            } else {
                BluetoothGattDescriptor.ENABLE_INDICATION_VALUE
            }
            try {
                if (Build.VERSION.SDK_INT >= 33) {
                    g.writeDescriptor(cccd, value)
                } else {
                    cccd.value = value
                    g.writeDescriptor(cccd)
                }
            } catch (e: SecurityException) {
                listener.onLog("subscribe denied by permission")
            }
        }
    }

    fun read(characteristic: BluetoothGattCharacteristic) {
        enqueue {
            val g = gatt ?: return@enqueue
            try {
                g.readCharacteristic(characteristic)
            } catch (e: SecurityException) {
                listener.onLog("read denied by permission")
            }
        }
    }

    // ------------------------------------------------------------------ queue

    private fun enqueue(op: () -> Unit) {
        queue.addLast(op)
        pump()
    }

    private fun pump() {
        if (pumping) return
        if (queue.isEmpty()) return
        val op = queue.removeFirst()
        pumping = true
        try {
            op()
        } catch (t: Throwable) {
            listener.onLog("GATT operation failed: ${t.message}")
        }
        handler.postDelayed({
            pumping = false
            pump()
        }, OP_GAP_MS)
    }

    // --------------------------------------------------------------- helpers

    fun characteristic(gatt: BluetoothGatt, uuid: java.util.UUID): BluetoothGattCharacteristic? {
        for (service in gatt.services) {
            for (c in service.characteristics) {
                if (c.uuid == uuid) return c
            }
        }
        return null
    }

    private fun adapter(): BluetoothAdapter? {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        return manager?.adapter
    }

    // ------------------------------------------------------------- callbacks

    @Suppress("DEPRECATION")
    fun writeCompat(
        g: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        value: ByteArray,
        writeType: Int,
    ) {
        if (Build.VERSION.SDK_INT >= 33) {
            g.writeCharacteristic(characteristic, value, writeType)
        } else {
            characteristic.writeType = writeType
            characteristic.value = value
            g.writeCharacteristic(characteristic)
        }
    }

    @Suppress("DEPRECATION")
    private val callback = object : BluetoothGattCallback() {

        override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                retryBudget = 1
                listener.onLog("connected (status ${gattStatusName(status)})")
                listener.onConnected(g)
                enqueue { g.requestMtu(MTU_REQUEST) }
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                listener.onLog("disconnected (status ${gattStatusName(status)})")
                if (gatt === g) gatt = null

                // 133 immediately after connecting almost always means another
                // central already holds the peripheral -- on a Xiaomi phone that
                // is usually Mi Fitness keeping the band connected. Retry once,
                // after saying so, because "reconnect" alone is not advice.
                val address = lastAddress
                if (status == 133 && retryBudget > 0 && address != null) {
                    retryBudget--
                    listener.onLog(
                        "133 usually means another app holds the band (Mi Fitness). " +
                            "Force-stop it, then retry -- or unpair the band first."
                    )
                    handler.postDelayed({ connect(address) }, 1_500L)
                    return
                }
                listener.onDisconnected(status)
            }
        }

        override fun onMtuChanged(g: BluetoothGatt, mtu: Int, status: Int) {
            listener.onLog("MTU = $mtu")
            enqueue { g.discoverServices() }
        }

        override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                listener.onError("service discovery", status)
                return
            }
            listener.onServicesReady(g)
        }

        override fun onCharacteristicChanged(
            g: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
        ) {
            listener.onNotify(characteristic, value)
        }

        override fun onCharacteristicChanged(
            g: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
        ) {
            // On API 33+ the byte[] overload above is the one that fires.
            if (Build.VERSION.SDK_INT < 33) {
                listener.onNotify(characteristic, characteristic.value ?: ByteArray(0))
            }
        }

        override fun onCharacteristicWrite(
            g: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int,
        ) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                listener.onLog(
                    "write failed on ${MibandProtocol.uuidLabel(characteristic.uuid)}: " +
                        gattStatusName(status)
                )
            }
        }

        override fun onDescriptorWrite(
            g: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int,
        ) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                listener.onLog("subscribe failed: ${gattStatusName(status)}")
            }
        }
    }
}

/**
 * Turn an ATT status into something that tells you what to do next.
 *
 * `133` in particular is not a protocol error: it is Android's catch-all for a
 * GATT stack that has lost track of a connection, and the fix is to reconnect,
 * not to change your bytes.
 */
fun gattStatusName(status: Int): String = when (status) {
    0 -> "ok"
    1 -> "invalid handle"
    2 -> "read not permitted"
    3 -> "write not permitted"
    5 -> "insufficient authentication (bond the device first)"
    6 -> "request not supported"
    8 -> "insufficient authorization"
    12 -> "insufficient encryption key size"
    13 -> "invalid attribute length"
    14 -> "unlikely error"
    15 -> "insufficient encryption (pair/bond first)"
    17 -> "insufficient resources (slow the GATT queue)"
    18 -> "database out of sync"
    129 -> "GATT internal error (129)"
    133 -> "GATT_ERROR 133 -- stack lost the connection; reconnect"
    137 -> "GATT_ERROR 137 -- reconnect"
    143 -> "GATT_ERROR 143 -- reconnect"
    else -> "status $status"
}
