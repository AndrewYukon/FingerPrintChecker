package com.fpchecker

import org.json.JSONException
import org.json.JSONObject

internal object ResponseParser {

    /** Parses a challenge response; null when there is no usable nonce. */
    fun parseNonce(body: String): String? = try {
        JSONObject(body).optString("nonce", "").ifEmpty { null }
    } catch (_: JSONException) {
        null
    }

    fun parseIdentify(body: String, httpStatus: Int): FpResult {
        val json = try {
            JSONObject(body)
        } catch (_: JSONException) {
            return FpResult.Failure("bad_response", httpStatus)
        }
        val visitorId = json.optString("visitorId", "")
        val ok = json.optBoolean("ok", false)
        if (!ok || visitorId.isEmpty() || json.isNull("visitorId")) {
            val reason = json.optString("reason", "").ifEmpty { "bad_response" }
            return FpResult.Failure(reason, httpStatus)
        }
        fun strings(key: String): List<String> {
            val arr = json.optJSONArray(key) ?: return emptyList()
            return List(arr.length()) { arr.opt(it) }.filterIsInstance<String>()
        }
        val attestation = if (json.isNull("attestation")) null else json.opt("attestation")?.toString()
        return FpResult.Success(
            visitorId = visitorId,
            trustScore = if (json.has("trustScore")) json.optInt("trustScore") else null,
            identityConfidence = if (json.has("identityConfidence")) json.optInt("identityConfidence") else null,
            isNew = json.optBoolean("isNew", false),
            attestation = attestation,
            trustDeductions = strings("trustDeductions"),
            shadowDeductions = strings("shadowDeductions"),
            proofStatus = json.opt("proofStatus") as? String,
            eventId = (json.opt("eventId") as? String)?.ifEmpty { null },
            rawJson = body,
        )
    }

    /** Parses a v2 challenge response; null when there is no usable challenge. */
    fun parseChallengeV2(body: String): String? = try {
        val json = JSONObject(body)
        if (json.optBoolean("ok", false)) json.opt("challenge") as? String else null
    } catch (_: JSONException) {
        null
    }

    /** Server error code of a failed v2 response (`reason` or `error`), null when absent. */
    fun parseErrorV2(body: String): String? = try {
        val json = JSONObject(body)
        ((json.opt("reason") as? String) ?: (json.opt("error") as? String))?.ifEmpty { null }
    } catch (_: JSONException) {
        null
    }

    /** A success without a non-empty string `attestation` is a failure. */
    fun parseIdentifyV2(body: String, httpStatus: Int): FpIdentifyResult {
        val json = try {
            JSONObject(body)
        } catch (_: JSONException) {
            return FpIdentifyResult.Failure("bad_response", httpStatus)
        }
        val attestation = json.opt("attestation") as? String
        if (!json.optBoolean("ok", false) || attestation.isNullOrEmpty()) {
            return FpIdentifyResult.Failure(parseErrorV2(body) ?: "bad_response", httpStatus)
        }
        fun strings(key: String): List<String> {
            val arr = json.optJSONArray(key) ?: return emptyList()
            return List(arr.length()) { arr.opt(it) }.filterIsInstance<String>()
        }
        fun has(key: String) = json.has(key) && !json.isNull(key)
        return FpIdentifyResult.Success(
            attestation = attestation,
            expiresIn = if (has("expiresIn")) json.optInt("expiresIn") else null,
            proofStatus = json.opt("proofStatus") as? String,
            visitorId = json.opt("visitorId") as? String,
            trustScore = if (has("trustScore")) json.optInt("trustScore") else null,
            identityConfidence = if (has("identityConfidence")) json.optInt("identityConfidence") else null,
            isNew = if (has("isNew")) json.optBoolean("isNew") else null,
            trustDeductions = strings("trustDeductions"),
            shadowDeductions = strings("shadowDeductions"),
            rulesVersion = json.opt("rulesVersion") as? String,
            eventId = (json.opt("eventId") as? String)?.ifEmpty { null },
            rawJson = body,
        )
    }
}
