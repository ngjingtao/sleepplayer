package dev.remiband.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Protocol-level tests, mirroring the Python suite in `tests/test_pipeline.py`
 * so the two implementations cannot drift apart silently.
 */
class ProtocolTest {

    @Test
    fun `hex round trip`() {
        val bytes = byteArrayOf(0xA0.toByte(), 0x01, 0x00, 0xFF.toByte())
        assertEquals("a0 01 00 ff", Hex.encode(bytes))
        assertArrayEquals(bytes, Hex.decode("a0 01 00 ff"))
    }

    @Test
    fun `hex accepts separators`() {
        val expected = byteArrayOf(0x01, 0x02, 0x03)
        assertArrayEquals(expected, Hex.decode("01:02:03"))
        assertArrayEquals(expected, Hex.decode("01-02-03"))
        assertArrayEquals(expected, Hex.decode("010203"))
    }

    @Test
    fun `hex rejects garbage`() {
        assertNull(Hex.decode("0"))
        assertNull(Hex.decode("zz"))
        assertNull(Hex.decode(""))
        assertNull(Hex.decode("0102 0"))
    }

    @Test
    fun `aes matches the fips-197 vector`() {
        val key = byteArrayOf(
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        )
        val plain = byteArrayOf(
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88.toByte(), 0x99.toByte(), 0xAA.toByte(), 0xBB.toByte(),
            0xCC.toByte(), 0xDD.toByte(), 0xEE.toByte(), 0xFF.toByte(),
        )
        assertEquals(
            "69c4e0d86a7b0430d8cdb78070b4c55a",
            Hex.encode(Crypto.aesEcbBlock(key, plain), ""),
        )
    }

    @Test
    fun `command is chunked at sixteen payload bytes`() {
        val payload = ByteArray(18) { it.toByte() }
        val chunks = MibandProtocol.encodeCommand(0x0A, payload)

        assertEquals(2, chunks.size)
        assertEquals(20, chunks[0].size)
        assertEquals(0xA0, chunks[0][0].toInt() and 0xFF)
        assertEquals(0x0A, chunks[0][1].toInt() and 0xFF)
        assertEquals(0, chunks[0][2].toInt())
        assertEquals(16, chunks[0][3].toInt())

        assertEquals(6, chunks[1].size)
        assertEquals(1, chunks[1][2].toInt())
        assertEquals(2, chunks[1][3].toInt())
    }

    @Test
    fun `short command is a single chunk`() {
        val chunks = MibandProtocol.encodeCommand(0x02, byteArrayOf(1, 2, 3))
        assertEquals(1, chunks.size)
        assertEquals(3, chunks[0][3].toInt())
    }

    @Test
    fun `empty payload still produces a header`() {
        val chunks = MibandProtocol.encodeCommand(0x13, ByteArray(0))
        assertEquals(1, chunks.size)
        assertEquals(4, chunks[0].size)
        assertEquals(0, chunks[0][3].toInt())
    }

    @Test
    fun `decodes a command frame`() {
        val raw = byteArrayOf(0xA0.toByte(), 0x02, 0x00, 0x02, 0xEA.toByte(), 0x07)
        val frame = MibandProtocol.decodeFrame(raw, fromBand = false)!!

        assertEquals(MibandProtocol.Kind.COMMAND, frame.kind)
        assertEquals(0x02, frame.cmd)
        assertEquals(0, frame.seq)
        assertArrayEquals(byteArrayOf(0xEA.toByte(), 0x07), frame.payload)
    }

    @Test
    fun `decodes a band response`() {
        val raw = byteArrayOf(0xA0.toByte(), 0x01, 0x0E, 0x01)
        val frame = MibandProtocol.decodeFrame(raw, fromBand = true)!!

        assertEquals(MibandProtocol.Kind.RESPONSE, frame.kind)
        assertEquals(0x0E, frame.cmd)
        assertEquals(1, frame.status)
    }

    @Test
    fun `rejects unframed payloads`() {
        assertNull(MibandProtocol.decodeFrame(byteArrayOf(0x01, 0x08), fromBand = false))
        assertNull(MibandProtocol.decodeFrame(ByteArray(0), fromBand = false))
    }

    @Test
    fun `auth state machine reaches authenticated`() {
        val key = ByteArray(16) { it.toByte() }
        val nonce = Hex.decode("00112233445566778899aabbccddeeff")!!
        val session = AuthSession(key)

        session.onWrite(session.nextWrite()!!)
        session.onNotify(byteArrayOf(0x10, 0x01, 0x01))
        session.onWrite(session.nextWrite()!!)
        session.onNotify(byteArrayOf(0x10, 0x02, 0x01) + nonce)
        session.onWrite(session.nextWrite()!!)
        session.onNotify(byteArrayOf(0x10, 0x03, 0x01))

        assertTrue(session.succeeded)
        assertArrayEquals(nonce, session.nonce!!)
        assertTrue("our own response must be reproducible", session.keyConsistent == true)
    }

    @Test
    fun `auth flags a key that does not match`() {
        val nonce = Hex.decode("00112233445566778899aabbccddeeff")!!
        val captured = Hex.decode("69c4e0d86a7b0430d8cdb78070b4c55a")!!

        val session = AuthSession(ByteArray(16))
        session.onNotify(byteArrayOf(0x10, 0x02, 0x01) + nonce)
        // Replay the response from a capture made with a different key.
        session.onWrite(byteArrayOf(0x03, 0x00) + captured)

        assertEquals(false, session.keyConsistent)
    }
}
