package dev.remiband.core

/**
 * Hex formatting and parsing, shared by the probe screen and the protocol layer.
 *
 * Parsing is deliberately forgiving about separators (` `, `:`, `-`, `,`) and
 * strict about everything else: a half-byte is a mistake, not something to
 * guess at.
 */
object Hex {

    private const val DIGITS = "0123456789abcdef"

    fun encode(data: ByteArray, separator: String = " "): String {
        if (data.isEmpty()) return ""
        val out = StringBuilder(data.size * 3)
        for (i in data.indices) {
            if (i > 0) out.append(separator)
            val v = data[i].toInt() and 0xFF
            out.append(DIGITS[v shr 4])
            out.append(DIGITS[v and 0x0F])
        }
        return out.toString()
    }

    /** Returns null when the text is not an even-length run of hex digits. */
    fun decode(text: String): ByteArray? {
        val clean = text.filter { !it.isWhitespace() && it != ':' && it != '-' && it != ',' }
        if (clean.isEmpty() || clean.length % 2 != 0) return null
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            val hi = digit(clean[i * 2]) ?: return null
            val lo = digit(clean[i * 2 + 1]) ?: return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    private fun digit(c: Char): Int? = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> null
    }
}
