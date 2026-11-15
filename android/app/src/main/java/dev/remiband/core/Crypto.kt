package dev.remiband.core

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * The only crypto the Mi Band handshake needs: one AES-128 ECB block.
 *
 * `javax.crypto` ships with Android, so this costs no dependency. The Python
 * side of this project carries a hand-rolled AES for environments without one;
 * here the platform's implementation is used, which is both faster and
 * constant-time.
 */
object Crypto {

    fun aesEcbBlock(key: ByteArray, block: ByteArray): ByteArray {
        require(key.size == 16) { "AES-128 key must be 16 bytes, got ${key.size}" }
        require(block.size == 16) { "AES block must be 16 bytes, got ${block.size}" }

        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return cipher.doFinal(block)
    }
}
