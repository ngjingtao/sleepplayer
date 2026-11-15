package dev.remiband.core

import java.util.UUID

/**
 * The classic Mi Band envelope and its authentication handshake.
 *
 * Ported from `remiband/miband.py`, where it is covered by tests against a
 * synthetic capture. Two things to keep in mind when reading it:
 *
 *  * it decodes *structure* (0xA0 envelope, seq/len, 0x10 control codes) and
 *    never invents the meaning of a command id -- id semantics are the part
 *    this project deliberately leaves to evidence;
 *  * it is the Mi Band 2-6 generation format. A band newer than that may not
 *    speak it at all, which is what `ProbeActivity` is for.
 */
object MibandProtocol {

    const val MARKER = 0xA0

    /** Payload bytes per chunk: 20-byte ATT value minus the 4-byte header. */
    const val CHUNK_PAYLOAD = 16

    val AUTH_UUID: UUID = UUID.fromString("00000009-0000-3512-2118-0009af100700")
    val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    val CONTROL_POINT: UUID = UUID.fromString("0000ff05-0000-1000-8000-00805f9b34fb")
    val NOTIFY_CHAR: UUID = UUID.fromString("0000ff03-0000-1000-8000-00805f9b34fb")
    /** Standard GATT Heart Rate service and measurement.
     *
     * Many bands do not expose these -- the Mi Band family normally keeps heart
     * rate on a vendor characteristic -- but when a device *does* expose them
     * the format is defined by the spec, so this is free correctness: no
     * guessing, no byte-offset setting. */
    val HR_SERVICE: UUID = UUID.fromString("0000180d-0000-1000-8000-00805f9b34fb")
    val HR_MEASUREMENT: UUID = UUID.fromString("00002a37-0000-1000-8000-00805f9b34fb")

    val HEART_RATE_CONTROL: UUID = UUID.fromString("0000ff11-0000-1000-8000-00805f9b34fb")
    val HEART_RATE_DATA: UUID = UUID.fromString("0000ff12-0000-1000-8000-00805f9b34fb")

    val AUTH_START: ByteArray = byteArrayOf(0x01, 0x08)
    val AUTH_NONCE_REQ: ByteArray = byteArrayOf(0x02, 0x00)
    private const val AUTH_RESPONSE_OP = 0x03
    private const val AUTH_NOTIFY_PREFIX = 0x10

    enum class Kind { COMMAND, RESPONSE, RAW }

    class Frame(
        val kind: Kind,
        val raw: ByteArray,
        val cmd: Int?,
        val seq: Int,
        val status: Int?,
        val payload: ByteArray,
    )

    // ---------------------------------------------------------------- decode

    fun decodeFrame(data: ByteArray, fromBand: Boolean): Frame? {
        if (data.isEmpty()) return null
        if ((data[0].toInt() and 0xFF) != MARKER) return null

        if (fromBand) {
            // a0 01 <type> <status> <payload>
            if (data.size >= 4 && (data[1].toInt() and 0xFF) == 0x01) {
                return Frame(
                    Kind.RESPONSE,
                    data,
                    data[2].toInt() and 0xFF,
                    0,
                    data[3].toInt() and 0xFF,
                    if (data.size > 4) data.copyOfRange(4, data.size) else ByteArray(0),
                )
            }
            return Frame(
                Kind.RAW,
                data,
                null,
                0,
                null,
                if (data.size > 1) data.copyOfRange(1, data.size) else ByteArray(0),
            )
        }

        // a0 <cmd> <seq> <len> <payload>
        if (data.size < 3) return Frame(Kind.RAW, data, null, 0, null, ByteArray(0))
        val start = if (data.size >= 4) 4 else data.size
        val declared = if (data.size >= 4) data[3].toInt() and 0xFF else 0
        val payload = when {
            declared > 0 && start + declared <= data.size ->
                data.copyOfRange(start, start + declared)
            data.size > start -> data.copyOfRange(start, data.size)
            else -> ByteArray(0)
        }
        return Frame(
            Kind.COMMAND,
            data,
            data[1].toInt() and 0xFF,
            data[2].toInt() and 0xFF,
            null,
            payload,
        )
    }

    // ---------------------------------------------------------------- encode

    /**
     * Split one command into the ATT-sized chunks the band expects.
     *
     * A chunk shorter than [CHUNK_PAYLOAD] ends the message; that single rule
     * is what lets the other side reassemble without any length-of-message
     * field.
     */
    fun encodeCommand(cmd: Int, payload: ByteArray): List<ByteArray> {
        val chunks = ArrayList<ByteArray>()
        if (payload.isEmpty()) {
            chunks.add(byteArrayOf(MARKER.toByte(), cmd.toByte(), 0, 0))
            return chunks
        }
        var offset = 0
        var seq = 0
        while (offset < payload.size) {
            val n = minOf(CHUNK_PAYLOAD, payload.size - offset)
            val out = ByteArray(4 + n)
            out[0] = MARKER.toByte()
            out[1] = cmd.toByte()
            out[2] = seq.toByte()
            out[3] = n.toByte()
            System.arraycopy(payload, offset, out, 4, n)
            chunks.add(out)
            offset += n
            seq++
        }
        return chunks
    }

    // ------------------------------------------------------- heart rate decode

    /**
     * Decode a standard GATT Heart Rate Measurement (0x2A37).
     *
     * Byte 0 is a flags field; bit 0 selects an 8- or 16-bit bpm that follows.
     * Returning null for implausible values is deliberate: a band that reports
     * 0 while no sensor contact is established must not be read as "bpm 0,
     * therefore deeply asleep".
     */
    fun decodeHeartRateMeasurement(value: ByteArray): Int? {
        if (value.isEmpty()) return null
        val flags = value[0].toInt() and 0xFF
        val wide = (flags and 0x01) != 0
        return if (!wide) {
            if (value.size < 2) return null
            (value[1].toInt() and 0xFF).takeIf { it in 25..250 }
        } else {
            if (value.size < 3) return null
            val bpm = (value[1].toInt() and 0xFF) or ((value[2].toInt() and 0xFF) shl 8)
            bpm.takeIf { it in 25..250 }
        }
    }

    // ----------------------------------------------------------------- names

    fun isXiaomi(uuid: UUID): Boolean =
        uuid.toString().endsWith("-0000-3512-2118-0009af100700")

    fun uuidLabel(uuid: UUID): String = when (uuid) {
        AUTH_UUID -> "mi auth"
        CONTROL_POINT -> "ff05 control point"
        NOTIFY_CHAR -> "ff03 notification"
        HR_SERVICE -> "180d heart rate (standard)"
        HR_MEASUREMENT -> "2a37 hr measurement (standard)"
        HEART_RATE_CONTROL -> "ff11 heart-rate control"
        HEART_RATE_DATA -> "ff12 heart-rate data"
        CCCD_UUID -> "2902 CCCD"
        in STANDARD -> STANDARD.getValue(uuid)
        else -> if (isXiaomi(uuid)) "xiaomi ${uuid.toString().substring(4, 8)}" else uuid.toString()
    }

    private val STANDARD: Map<UUID, String> = buildMap {
        fun add(s: String, n: String) = put(UUID.fromString(s), n)
        add("00001800-0000-1000-8000-00805f9b34fb", "1800 generic access")
        add("00001801-0000-1000-8000-00805f9b34fb", "1801 gatt")
        add("0000180a-0000-1000-8000-00805f9b34fb", "180a device info")
        add("0000180d-0000-1000-8000-00805f9b34fb", "180d heart rate")
        add("0000180f-0000-1000-8000-00805f9b34fb", "180f battery")
        add("0000fee0-0000-1000-8000-00805f9b34fb", "fee0 mi band")
        add("0000fee1-0000-1000-8000-00805f9b34fb", "fee1 mi band auth")
        add("00002a00-0000-1000-8000-00805f9b34fb", "2a00 device name")
        add("00002a19-0000-1000-8000-00805f9b34fb", "2a19 battery level")
        add("00002a37-0000-1000-8000-00805f9b34fb", "2a37 heart rate measurement")
    }
}

/**
 * Narrates -- and lets the app drive -- the AES-128 challenge/response.
 *
 * The state machine mirrors the Python `AuthSession` exactly, including the
 * distinction that matters most: [succeeded] is what the *band* said, while
 * [keyConsistent] is whether the key we hold actually reproduces the observed
 * response. Those can disagree, and silently treating a wrong key as success
 * is how you spend an evening debugging a handshake that was never the problem.
 */
class AuthSession(private val key: ByteArray?) {

    enum class State { IDLE, START_SENT, READY, NONCE_REQUESTED, CHALLENGE_SENT, AUTHENTICATED, FAILED }

    var state: State = State.IDLE
        private set

    var nonce: ByteArray? = null
        private set

    var response: ByteArray? = null
        private set

    var keyConsistent: Boolean? = null
        private set

    val events: MutableList<String> = ArrayList()

    val succeeded: Boolean get() = state == State.AUTHENTICATED

    private fun computeResponse(): ByteArray? {
        val k = key ?: return null
        val n = nonce ?: return null
        if (k.size != 16 || n.size != 16) return null
        return Crypto.aesEcbBlock(k, n)
    }

    fun onWrite(value: ByteArray) {
        when {
            value.contentEquals(MibandProtocol.AUTH_START) -> {
                state = State.START_SENT
                events.add("start auth (01 08)")
            }
            value.contentEquals(MibandProtocol.AUTH_NONCE_REQ) -> {
                state = State.NONCE_REQUESTED
                events.add("request nonce (02 00)")
            }
            value.size == 18 && (value[0].toInt() and 0xFF) == 0x03 -> {
                state = State.CHALLENGE_SENT
                val expected = computeResponse()
                keyConsistent = expected?.contentEquals(value.copyOfRange(2, 18))
                events.add(
                    if (keyConsistent == false) "sent response -- KEY DOES NOT MATCH"
                    else "sent response"
                )
            }
            else -> events.add("write ${Hex.encode(value)}")
        }
    }

    fun onNotify(value: ByteArray) {
        if (value.isEmpty() || (value[0].toInt() and 0xFF) != 0x10) {
            events.add("unexpected notify ${Hex.encode(value)}")
            return
        }
        val sub = if (value.size > 1) value[1].toInt() and 0xFF else -1
        val code = if (value.size > 2) value[2].toInt() and 0xFF else -1

        when (sub) {
            0x01 -> if (code == 0x01) {
                state = State.READY
                events.add("ready (10 01 01)")
            } else {
                events.add("10 01 " + Hex.encode(byteArrayOf(code.toByte())))
            }

            0x02 -> if (code == 0x01 && value.size >= 19) {
                nonce = value.copyOfRange(3, 19)
                response = computeResponse()
                state = State.NONCE_REQUESTED
                events.add("nonce ${Hex.encode(nonce!!)}")
            } else {
                events.add("nonce rejected")
            }

            0x03 -> if (code == 0x01) {
                state = State.AUTHENTICATED
                events.add("AUTHENTICATED")
            } else {
                state = State.FAILED
                events.add("AUTH FAILED (wrong key)")
            }

            else -> events.add("notify ${Hex.encode(value)}")
        }
    }

    /** The next byte string to write, or null when we are waiting on the band. */
    fun nextWrite(): ByteArray? = when (state) {
        State.IDLE -> MibandProtocol.AUTH_START
        State.READY -> MibandProtocol.AUTH_NONCE_REQ
        State.NONCE_REQUESTED -> response?.let { byteArrayOf(0x03, 0x00) + it }
        else -> null
    }
}
