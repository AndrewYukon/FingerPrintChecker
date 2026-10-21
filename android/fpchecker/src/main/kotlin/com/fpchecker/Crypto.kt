package com.fpchecker

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal object Crypto {
    private val HEX = "0123456789abcdef".toCharArray()

    fun toHex(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xff
            out[i * 2] = HEX[v ushr 4]
            out[i * 2 + 1] = HEX[v and 0x0f]
        }
        return String(out)
    }

    fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    fun sha256Hex(text: String): String = toHex(sha256(text.toByteArray(Charsets.UTF_8)))

    /** Lowercase hex HMAC-SHA256; key and message are the UTF-8 bytes of the strings. */
    fun hmacSha256Hex(key: String, message: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return toHex(mac.doFinal(message.toByteArray(Charsets.UTF_8)))
    }
}
