package com.fpchecker

import java.security.MessageDigest

internal object Pow {
    const val MIN_BITS = 8
    const val MAX_BITS = 28

    fun leadingZeroBits(digest: ByteArray): Int {
        var bits = 0
        for (b in digest) {
            val v = b.toInt() and 0xff
            if (v == 0) {
                bits += 8
                continue
            }
            return bits + Integer.numberOfLeadingZeros(v) - 24
        }
        return bits
    }

    /**
     * Smallest decimal counter c >= 0 such that SHA-256(UTF-8 "nonce:c") has at least [bits]
     * leading zero bits. Returns null if [keepGoing] turns false (cancellation).
     * The result is a String on purpose: the wire format requires a JSON string.
     */
    fun solve(nonce: String, bits: Int, keepGoing: () -> Boolean = { true }): String? {
        require(bits in MIN_BITS..MAX_BITS) { "bits out of range" }
        val md = MessageDigest.getInstance("SHA-256")
        var counter = 0L
        while (true) {
            if (counter and 0xfffL == 0L && !keepGoing()) return null
            val digest = md.digest("$nonce:$counter".toByteArray(Charsets.UTF_8))
            if (leadingZeroBits(digest) >= bits) return counter.toString()
            counter++
        }
    }
}
