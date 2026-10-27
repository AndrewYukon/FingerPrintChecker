package com.fpchecker.reactnative

import com.fpchecker.FpCheckerConfig
import com.fpchecker.FpEventOptions
import com.fpchecker.FpIdentifyResult
import kotlinx.coroutines.CancellationException
import java.util.concurrent.ConcurrentHashMap

/*
 * Pure bridge logic on Map<String, Any?> so JVM tests need no React Native runtime.
 * ReadableMap / WritableMap conversion lives in FingerPrintCheckerModule.
 */

private val LOOPBACK_HOSTS = setOf("localhost", "127.0.0.1", "::1", "[::1]")

private fun fail(reason: String, httpStatus: Int = 0) = failureReply(reason, httpStatus)

internal fun failureReply(reason: String, httpStatus: Int): Map<String, Any?> =
    mapOf("ok" to false, "reason" to reason, "httpStatus" to httpStatus)

internal fun replyOf(result: FpIdentifyResult): Map<String, Any?> = when (result) {
    is FpIdentifyResult.Failure -> failureReply(result.reason, result.httpStatus)
    is FpIdentifyResult.Success -> buildMap {
        put("ok", true)
        put("visitorId", result.visitorId)
        put("attestation", result.attestation)
        result.eventId?.let { put("eventId", it) }
        result.trustScore?.let { put("trustScore", it) }
        result.identityConfidence?.let { put("identityConfidence", it) }
        result.isNew?.let { put("isNew", it) }
        put("trustDeductions", result.trustDeductions.toList())
        put("shadowDeductions", result.shadowDeductions.toList())
        result.proofStatus?.let { put("proofStatus", it) }
        result.expiresIn?.let { put("expiresIn", it) }
        result.rulesVersion?.let { put("rulesVersion", it) }
        result.sealedResult?.let { put("sealedResult", it) }
        put("rawJson", result.rawJson)
    }
}

private fun hostOf(url: String): String {
    val rest = url.substringAfter("://")
    val authority = rest.substringBefore('/').substringBefore('?').substringBefore('#').substringAfterLast('@')
    return if (authority.startsWith("[")) authority.substringBefore(']') + "]" else authority.substringBefore(':')
}

private fun wholeNumber(v: Any?, field: String): Long? = when (v) {
    null -> null
    is Number -> {
        val d = v.toDouble()
        require(d.isFinite() && d == Math.rint(d)) { "$field must be a whole number" }
        v.toLong()
    }
    else -> throw IllegalArgumentException("$field must be a number")
}

/** Throws [IllegalArgumentException] on a bad config. `sealKey` is never read: v2 does not use it. */
internal fun configFrom(map: Map<String, Any?>): FpCheckerConfig {
    val pk = map["publishableKey"]
    require(pk is String && pk.isNotBlank()) { "publishableKey is required" }
    val baseUrl = when (val b = map["baseUrl"]) {
        null -> FpCheckerConfig.DEFAULT_BASE_URL
        is String -> b
        else -> throw IllegalArgumentException("baseUrl must be a string")
    }
    if (baseUrl.startsWith("http://")) {
        require(hostOf(baseUrl).lowercase() in LOOPBACK_HOSTS) { "http baseUrl is only allowed on loopback" }
    }
    val probes = when (val p = map["integrityProbes"]) {
        null -> true
        is Boolean -> p
        else -> throw IllegalArgumentException("integrityProbes must be a boolean")
    }
    val pow = wholeNumber(map["powDifficulty"], "powDifficulty")
    require(pow == null || pow in Int.MIN_VALUE..Int.MAX_VALUE) { "powDifficulty out of range" }
    return FpCheckerConfig(
        baseUrl = baseUrl,
        publishableKey = pk,
        cloudProjectNumber = wholeNumber(map["cloudProjectNumber"], "cloudProjectNumber"),
        powDifficulty = pow?.toInt(),
        integrityTimeoutMillis = wholeNumber(map["integrityTimeoutMillis"], "integrityTimeoutMillis") ?: 5_000L,
        integrityProbes = probes,
    )
}

/** Canonical, key-order independent string for a config map; identifies the native instance. */
private fun canonicalKey(value: Any?): String = when (value) {
    is Map<*, *> -> value.entries.sortedBy { it.key.toString() }
        .joinToString(",", "{", "}") { "${it.key}:${canonicalKey(it.value)}" }
    is List<*> -> value.joinToString(",", "[", "]") { canonicalKey(it) }
    is Number -> value.toDouble().let { if (it == Math.rint(it) && it.isFinite()) it.toLong().toString() else it.toString() }
    is String -> "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
    else -> value.toString()
}

/** JS numbers arrive as Double; whole values become Long so tags serialise as integers. */
private fun normalizeTags(value: Any?): Any? = when (value) {
    is Map<*, *> -> value.entries.associate { it.key.toString() to normalizeTags(it.value) }
    is List<*> -> value.map(::normalizeTags)
    is Double -> if (value.isFinite() && value == Math.rint(value) && Math.abs(value) < 9.0e15) value.toLong() else value
    is Float -> normalizeTags(value.toDouble())
    else -> value
}

/** Narrow seam over [com.fpchecker.FpChecker] so tests can force failures. */
internal interface Identifier {
    suspend fun identify(intentToken: String, options: FpEventOptions): FpIdentifyResult
    fun close()
}

/**
 * Owns one [Identifier] per distinct config and turns every outcome into a reply map. [handle] never throws
 * (except coroutine cancellation, which must propagate).
 */
internal class IdentifyHandler(private val factory: (FpCheckerConfig) -> Identifier) {
    private val instances = ConcurrentHashMap<String, Identifier>()

    suspend fun handle(args: Map<String, Any?>): Map<String, Any?> {
        val configMap = (args["config"] as? Map<*, *>)?.entries?.associate { it.key.toString() to it.value }
            ?: return fail("bad_config")
        val config = try {
            configFrom(configMap)
        } catch (_: IllegalArgumentException) {
            return fail("bad_config")
        }
        val token = args["intentToken"]
        if (token !is String || token.isEmpty()) return fail("bad_intent_token")
        val linkedId = args["linkedId"] as? String
        @Suppress("UNCHECKED_CAST")
        val tags = normalizeTags(args["tags"]) as? Map<String, Any?>
        return try {
            val identifier = instances.computeIfAbsent(canonicalKey(configMap)) { factory(config) }
            replyOf(identifier.identify(token, FpEventOptions(linkedId = linkedId, tags = tags)))
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
            fail("bridge_error")
        }
    }

    fun close() {
        val all = instances.values.toList()
        instances.clear()
        all.forEach { runCatching { it.close() } }
    }
}
