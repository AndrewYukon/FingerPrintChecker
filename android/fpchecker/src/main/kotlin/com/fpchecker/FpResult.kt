package com.fpchecker

/** Outcome of [FpChecker.identify]. */
public sealed class FpResult {

    /**
     * The server accepted the request.
     *
     * [attestation] is an opaque token to forward to YOUR backend, which must verify it
     * (see the README); never make entitlement decisions from the other fields on the device.
     */
    public data class Success(
        val visitorId: String,
        val trustScore: Int,
        val identityConfidence: Int,
        val isNew: Boolean,
        val attestation: String?,
        val trustDeductions: List<String>,
        /** Rules that are scored but not yet weighted (shadow mode); for evaluation only. */
        val shadowDeductions: List<String> = emptyList(),
        /** `none`, `unconfigured`, `wrong_platform`, `unavailable`, `checked` or `unknown_key`; null from older servers. */
        val proofStatus: String? = null,
        val rawJson: String,
    ) : FpResult()

    /**
     * The request failed. [reason] is a server reason code (`bad_request`, `seal_invalid`, ...)
     * or one of the client-side codes `network`, `challenge_failed`, `bad_response`.
     * [httpStatus] is 0 when no HTTP response was received.
     */
    public data class Failure(val reason: String, val httpStatus: Int) : FpResult()
}
