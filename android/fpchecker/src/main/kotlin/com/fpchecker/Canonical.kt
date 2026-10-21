package com.fpchecker

internal object Canonical {
    /**
     * `nonce|k=v|k=v...`. The server sorts the joined `key=value` strings with a plain
     * UTF-16 code unit comparison (JS `Array.prototype.sort()`), which is what Kotlin's
     * natural String ordering does too.
     */
    fun payload(nonce: String, components: List<Component>): String =
        nonce + "|" + components.map { "${it.key}=${it.value}" }.sorted().joinToString("|")

    fun seal(sealKey: String, canonical: String): String = Crypto.hmacSha256Hex(sealKey, canonical)

    /** Play Integrity `requestHash`. */
    fun requestHash(canonical: String): String = Crypto.sha256Hex(canonical)
}
