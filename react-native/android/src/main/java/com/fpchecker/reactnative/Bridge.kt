package com.fpchecker.reactnative

import com.fpchecker.FpCheckerConfig
import com.fpchecker.FpEventOptions
import com.fpchecker.FpIdentifyResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean
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

/** https needs a host; http only on loopback; anything else (or unparsable) is rejected. Scheme is case-insensitive. */
private fun validBaseUrl(url: String): String {
    val uri = try { java.net.URI(url) } catch (_: java.net.URISyntaxException) { null }
    val scheme = uri?.scheme?.lowercase()
    val host = uri?.host?.lowercase()?.removePrefix("[")?.removeSuffix("]")
    require(!host.isNullOrEmpty()) { "baseUrl is not a valid URL" }
    when (scheme) {
        "https" -> Unit
        "http" -> require(host in LOOPBACK_HOSTS) { "http baseUrl is only allowed on loopback" }
        else -> throw IllegalArgumentException("baseUrl must be https")
    }
    // The native config only accepts a lowercase scheme prefix.
    return scheme + url.substring(url.indexOf(':'))
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
    val probes = when (val p = map["integrityProbes"]) {
        null -> true
        is Boolean -> p
        else -> throw IllegalArgumentException("integrityProbes must be a boolean")
    }
    val pow = wholeNumber(map["powDifficulty"], "powDifficulty")
    require(pow == null || pow in Int.MIN_VALUE..Int.MAX_VALUE) { "powDifficulty out of range" }
    return FpCheckerConfig(
        baseUrl = validBaseUrl(baseUrl),
        publishableKey = pk,
        cloudProjectNumber = wholeNumber(map["cloudProjectNumber"], "cloudProjectNumber"),
        powDifficulty = pow?.toInt(),
        integrityTimeoutMillis = wholeNumber(map["integrityTimeoutMillis"], "integrityTimeoutMillis") ?: 5_000L,
        integrityProbes = probes,
    )
}

/** Canonical string of the Android-relevant parsed fields; iOS-only or unknown keys never matter. */
internal fun instanceKey(c: FpCheckerConfig): String =
    "${c.baseUrl}|${c.publishableKey}|${c.cloudProjectNumber}|${c.powDifficulty}|${c.integrityTimeoutMillis}|${c.integrityProbes}"

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
 * (except coroutine cancellation, which must propagate). Work runs on [Dispatchers.Default], so the factory
 * (native SDK construction) never runs on the caller's (main) thread.
 */
internal class IdentifyHandler(private val factory: (FpCheckerConfig) -> Identifier) {
    private val instances = ConcurrentHashMap<String, Identifier>()

    suspend fun handle(args: Map<String, Any?>): Map<String, Any?> = try {
        withContext(Dispatchers.Default) { run(args) }
    } catch (e: CancellationException) {
        throw e
    } catch (_: Throwable) {
        fail("bridge_error")
    }

    private suspend fun run(args: Map<String, Any?>): Map<String, Any?> {
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
        val identifier = instances.computeIfAbsent(instanceKey(config)) { factory(config) }
        return replyOf(identifier.identify(token, FpEventOptions(linkedId = linkedId, tags = tags)))
    }

    fun close() {
        val all = instances.values.toList()
        instances.clear()
        all.forEach { runCatching { it.close() } }
    }
}

/** Resolves a promise exactly once; a converter failure falls back to a `bridge_error` reply. */
internal class OnceResolver<T>(private val convert: (Map<String, Any?>) -> T, private val resolve: (T) -> Unit) {
    private val done = AtomicBoolean(false)

    fun resolve(reply: Map<String, Any?>) {
        if (!done.compareAndSet(false, true)) return
        val out = try {
            convert(reply)
        } catch (_: Throwable) {
            convert(failureReply("bridge_error", 0))
        }
        resolve(out)
    }
}
