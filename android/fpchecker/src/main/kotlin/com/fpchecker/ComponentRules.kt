package com.fpchecker

import java.util.Locale

/**
 * Client-side mirror of the server's android component formats. The server rejects the whole
 * request on a wrong format, so every value is normalised here and omitted when unobtainable.
 * No android.* imports: this is unit-tested on the JVM.
 */
internal object ComponentRules {
    const val MAX_VALUE = 256
    const val BAD_ANDROID_ID = "9774d56d682e549c"

    const val ID = "android.id"
    const val MEDIA_DRM_ID = "android.mediaDrmId"
    const val SIM_COUNTRY = "android.simCountry"
    const val NETWORK_COUNTRY = "android.networkCountry"
    const val TIMEZONE = "android.timezone"
    const val BUILD_FINGERPRINT = "android.buildFingerprint"
    const val HARDWARE = "android.hardware"
    const val SDK_INT = "android.sdkInt"
    const val MODEL = "android.model"

    private val HEX16 = Regex("^[0-9a-f]{16}$")
    private val HEX64 = Regex("^[0-9a-f]{64}$")
    private val COUNTRY = Regex("^[a-z]{2}$")
    private val SDK = Regex("^[0-9]{1,3}$")

    private val MAX_LEN = mapOf(
        BUILD_FINGERPRINT to 256, HARDWARE to 64, MODEL to 64, TIMEZONE to MAX_VALUE,
    )

    private val IDENTITY_KEYS = setOf(ID, MEDIA_DRM_ID)

    /** Lowercase, left-pad to 16 hex chars; null if absent, non-hex, degenerate or the known-bad value. */
    fun normalizeAndroidId(raw: String?): String? {
        val v = raw?.trim()?.lowercase(Locale.ROOT).orEmpty()
        if (v.isEmpty() || v.length > 16 || !v.all { it in '0'..'9' || it in 'a'..'f' }) return null
        val padded = v.padStart(16, '0')
        if (padded == BAD_ANDROID_ID || padded.all { it == '0' }) return null
        return padded
    }

    /** hex(SHA-256(deviceUniqueId)); null for empty or all-zero ids. */
    fun hashMediaDrmId(raw: ByteArray?): String? {
        if (raw == null || raw.isEmpty() || raw.all { it == 0.toByte() }) return null
        return Crypto.toHex(Crypto.sha256(raw))
    }

    /** Lowercase 2-letter ISO code, or "" when absent/invalid (the server accepts an empty value). */
    fun normalizeCountry(raw: String?): String {
        val v = raw?.trim()?.lowercase(Locale.ROOT).orEmpty()
        return if (COUNTRY.matches(v)) v else ""
    }

    /** Truncation that never leaves half a surrogate pair at the cut. */
    fun truncateSafe(raw: String, max: Int): String {
        if (raw.length <= max) return raw
        var end = max
        if (end > 0 && Character.isHighSurrogate(raw[end - 1])) end--
        return raw.substring(0, end)
    }

    /** Violations (empty when the list would be accepted by the server). */
    fun validate(components: List<Component>): List<String> {
        val errors = mutableListOf<String>()
        val seen = HashSet<String>()
        for ((key, value) in components) {
            if (!seen.add(key)) errors += "duplicate key $key"
            if (value.length > MAX_VALUE) errors += "$key too long"
            val max = MAX_LEN[key]
            if (max != null && value.length > max) errors += "$key exceeds $max"
            when (key) {
                ID -> if (!HEX16.matches(value) || value == BAD_ANDROID_ID || value.all { it == '0' }) errors += "$key bad format"
                MEDIA_DRM_ID -> if (!HEX64.matches(value) || value.all { it == '0' }) errors += "$key bad format"
                SIM_COUNTRY, NETWORK_COUNTRY -> if (value.isNotEmpty() && !COUNTRY.matches(value)) errors += "$key bad format"
                SDK_INT -> if (!SDK.matches(value)) errors += "$key bad format"
                TIMEZONE, BUILD_FINGERPRINT, HARDWARE, MODEL -> if (value.isEmpty()) errors += "$key empty"
                else -> errors += "unknown key $key"
            }
        }
        if (components.none { it.key in IDENTITY_KEYS }) errors += "no identity key"
        return errors
    }

    /**
     * Assemble the final component list from raw platform readings. Unobtainable or invalid
     * values are omitted; country codes fall back to "".
     */
    fun build(raw: RawSignals): List<Component> {
        val out = ArrayList<Component>()
        normalizeAndroidId(raw.androidId)?.let { out += Component(ID, it) }
        hashMediaDrmId(raw.mediaDrmId)?.let { out += Component(MEDIA_DRM_ID, it) }
        out += Component(SIM_COUNTRY, normalizeCountry(raw.simCountry))
        out += Component(NETWORK_COUNTRY, normalizeCountry(raw.networkCountry))
        optionalText(raw.timezone, MAX_VALUE)?.let { out += Component(TIMEZONE, it) }
        optionalText(raw.buildFingerprint, 256)?.let { out += Component(BUILD_FINGERPRINT, it) }
        optionalText(raw.hardware, 64)?.let { out += Component(HARDWARE, it) }
        if (raw.sdkInt in 1..999) out += Component(SDK_INT, raw.sdkInt.toString())
        optionalText(raw.model, 64)?.let { out += Component(MODEL, it) }
        return out
    }

    private fun optionalText(raw: String?, max: Int): String? {
        val v = raw?.let { truncateSafe(it, max) }.orEmpty()
        return v.ifEmpty { null }
    }
}

/** Platform readings before normalisation. Null / empty means "could not be obtained". */
internal data class RawSignals(
    val androidId: String?,
    val mediaDrmId: ByteArray?,
    val simCountry: String?,
    val networkCountry: String?,
    val timezone: String?,
    val buildFingerprint: String?,
    val hardware: String?,
    val sdkInt: Int,
    val model: String?,
)
