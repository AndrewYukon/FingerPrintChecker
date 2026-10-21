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
            trustScore = json.optInt("trustScore", 0),
            identityConfidence = json.optInt("identityConfidence", 0),
            isNew = json.optBoolean("isNew", false),
            attestation = attestation,
            trustDeductions = strings("trustDeductions"),
            shadowDeductions = strings("shadowDeductions"),
            proofStatus = json.opt("proofStatus") as? String,
            rawJson = body,
        )
    }
}
