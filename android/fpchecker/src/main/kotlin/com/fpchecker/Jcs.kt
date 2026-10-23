package com.fpchecker

/** A component as it appears in the canonical object; `hash` is only ever set by the web agent (vectors). */
internal data class JcsComponent(val key: String, val value: String, val hash: String? = null)

/**
 * Canonical bytes of an identify v2 request: UTF-8 of the RFC 8785 (JCS) form of one fixed object.
 * Written by hand on purpose: platform JSON encoders escape '/', '<', U+2028 etc. differently.
 */
internal object Jcs {
    const val DOMAIN = "fpchecker.identify.v2"
    const val MAX_AGENT_VERSION = 64

    private val KEY = Regex("^[A-Za-z0-9._-]{1,64}$")
    private val HEX = "0123456789abcdef".toCharArray()

    /** Throws [IllegalArgumentException] for input the server would refuse with bad_request. */
    fun identifyBytes(
        platform: String,
        agentVersion: String,
        challenge: String,
        components: List<JcsComponent>,
    ): ByteArray = identify(platform, agentVersion, challenge, components).toByteArray(Charsets.UTF_8)

    /** Lower-case hex SHA-256 of the canonical bytes: the Play Integrity `requestHash`. */
    fun requestHashHex(bytes: ByteArray): String = Crypto.toHex(Crypto.sha256(bytes))

    fun identify(platform: String, agentVersion: String, challenge: String, components: List<JcsComponent>): String {
        require(agentVersion.length <= MAX_AGENT_VERSION) { "agentVersion too long" }
        val seen = HashSet<String>()
        for (c in components) {
            require(KEY.matches(c.key)) { "bad component key" }
            require(seen.add(c.key)) { "duplicate component key ${c.key}" }
        }
        val out = StringBuilder()
        out.append("{\"agentVersion\":"); string(out, agentVersion)
        out.append(",\"challenge\":"); string(out, challenge)
        out.append(",\"components\":[")
        // String natural order is UTF-16 code unit order, as JCS requires.
        components.sortedBy { it.key }.forEachIndexed { i, c ->
            if (i > 0) out.append(',')
            out.append('{')
            if (c.hash != null) { out.append("\"hash\":"); string(out, c.hash); out.append(',') }
            out.append("\"key\":"); string(out, c.key)
            out.append(",\"value\":"); string(out, c.value)
            out.append('}')
        }
        out.append("],\"domain\":\"").append(DOMAIN).append("\",\"platform\":")
        string(out, platform)
        out.append(",\"protocolVersion\":2}")
        return out.toString()
    }

    private fun string(out: StringBuilder, s: String) {
        out.append('"')
        var i = 0
        while (i < s.length) {
            val ch = s[i]
            when {
                Character.isHighSurrogate(ch) -> {
                    require(i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) { "lone surrogate" }
                    out.append(ch).append(s[i + 1])
                    i++
                }
                Character.isLowSurrogate(ch) -> throw IllegalArgumentException("lone surrogate")
                ch == '"' -> out.append("\\\"")
                ch == '\\' -> out.append("\\\\")
                ch == '\b' -> out.append("\\b")
                ch == '\u000c' -> out.append("\\f")
                ch == '\n' -> out.append("\\n")
                ch == '\r' -> out.append("\\r")
                ch == '\t' -> out.append("\\t")
                ch < ' ' -> out.append("\\u00").append(HEX[ch.code ushr 4]).append(HEX[ch.code and 0x0f])
                else -> out.append(ch)
            }
            i++
        }
        out.append('"')
    }
}
