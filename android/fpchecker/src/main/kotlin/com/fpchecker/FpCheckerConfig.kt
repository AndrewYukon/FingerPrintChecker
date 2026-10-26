package com.fpchecker

/**
 * @property baseUrl API origin, e.g. `https://api.fpchecker.com` (no trailing path).
 * @property publishableKey the project's public key, sent as `X-Publishable-Key`.
 * @property sealKey the project's seal key; only the v1 flow ([FpChecker.identify] without an intent) needs it.
 * @property cloudProjectNumber your Google Cloud project number; enables the Play Integrity proof.
 * @property powDifficulty proof-of-work difficulty in leading zero bits (8..28), or null for none.
 * @property integrityTimeoutMillis maximum time to wait for a Play Integrity token.
 * @property integrityProbes run the on-device integrity probes (root, hook, emulator, ...). When false the SDK still
 *   sends the probe component, with every probe reported as unavailable.
 */
public data class FpCheckerConfig @JvmOverloads constructor(
    val baseUrl: String = DEFAULT_BASE_URL,
    val publishableKey: String,
    val sealKey: String? = null,
    val cloudProjectNumber: Long? = null,
    val powDifficulty: Int? = null,
    val integrityTimeoutMillis: Long = 5_000L,
    val integrityProbes: Boolean = true,
) {
    init {
        require(baseUrl.startsWith("https://") || baseUrl.startsWith("http://")) { "baseUrl must be http(s)" }
        require(publishableKey.isNotBlank()) { "publishableKey is required" }
        require(sealKey == null || sealKey.isNotEmpty()) { "sealKey must not be empty" }
        require(powDifficulty == null || powDifficulty in Pow.MIN_BITS..Pow.MAX_BITS) {
            "powDifficulty must be in ${Pow.MIN_BITS}..${Pow.MAX_BITS}"
        }
        require(cloudProjectNumber == null || cloudProjectNumber > 0) { "cloudProjectNumber must be positive" }
    }

    // Do not leak secrets through logs.
    override fun toString(): String =
        "FpCheckerConfig(baseUrl=$baseUrl, cloudProjectNumber=$cloudProjectNumber, powDifficulty=$powDifficulty)"

    public companion object {
        public const val DEFAULT_BASE_URL: String = "https://api.fpchecker.com"
    }
}
