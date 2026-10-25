package com.fpchecker

/** Outcome of [FpChecker.identify] with an intent token (protocol v2). */
public sealed class FpIdentifyResult {

    /**
     * The server accepted the request. Forward [attestation] unchanged to YOUR backend, which
     * passes it to the decision endpoint; it is opaque, never parse or trust it on the device.
     *
     * The score fields are only present when the project enabled `scoreDetails`; they are for
     * display and evaluation, never for entitlement decisions on the device.
     */
    public data class Success(
        val attestation: String,
        val expiresIn: Int? = null,
        /** `none`, `unconfigured`, `wrong_platform`, `unavailable`, `checked` or `unknown_key`. */
        val proofStatus: String? = null,
        val visitorId: String? = null,
        val trustScore: Int? = null,
        val identityConfidence: Int? = null,
        val isNew: Boolean? = null,
        val trustDeductions: List<String> = emptyList(),
        val shadowDeductions: List<String> = emptyList(),
        val rulesVersion: String? = null,
        /** Id of the event this identify wrote (read it with your secret key); null from servers that predate events. */
        val eventId: String? = null,
        val rawJson: String,
    ) : FpIdentifyResult()

    /**
     * The request failed. [reason] is a server reason or error code (`bad_intent`, `bad_request`, ...)
     * or a client-side code: `network`, `challenge_failed`, `bad_response`, `no_device_id`,
     * `bad_intent_token`, `bad_canonical`, `invalid_linked_id`, `invalid_tags`. [httpStatus] is 0 when no HTTP response was received.
     */
    public data class Failure(val reason: String, val httpStatus: Int) : FpIdentifyResult()
}
