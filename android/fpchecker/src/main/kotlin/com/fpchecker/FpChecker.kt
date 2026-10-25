package com.fpchecker

import android.content.Context
import android.os.Handler
import android.os.Looper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException

/**
 * Entry point. Create one instance per process (it caches the Play Integrity provider) and call
 * [identify]. Prefer the intent-token flow (v2): no secret is embedded in the app. The v1 seal key
 * is embedded in your app and therefore only raises the bar for forged requests; trust decisions
 * belong to the attestation verified by your backend.
 */
public class FpChecker(context: Context, private val config: FpCheckerConfig) {
    private val appContext = context.applicationContext
    private val api = ApiClient(config.baseUrl, config.publishableKey)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mainHandler = Handler(Looper.getMainLooper())
    private val integrity: PlayIntegrityTokens? = config.cloudProjectNumber?.let {
        PlayIntegrityTokens(appContext, it, config.integrityTimeoutMillis)
    }

    /** Runs the full challenge -> collect -> seal -> identify flow. Never throws except on cancellation. */
    public suspend fun identify(): FpResult = identify(FpEventOptions())

    /** As [identify], also storing [options] (`linkedId`, `tags`) on the event. Invalid options fail before any request. */
    public suspend fun identify(options: FpEventOptions): FpResult = withContext(Dispatchers.IO) {
        try {
            run(options)
        } catch (_: IOException) {
            FpResult.Failure("network", 0)
        }
    }

    /** Callback variant for Java callers; [callback] is invoked on the main thread. */
    public fun identify(callback: FpCallback) {
        identify(FpEventOptions(), callback)
    }

    /** Callback variant of [identify] with [options]; [callback] is invoked on the main thread. */
    public fun identify(options: FpEventOptions, callback: FpCallback) {
        scope.launch {
            val result = identify(options)
            mainHandler.post { callback.onResult(result) }
        }
    }

    /** Cancels in-flight callback-style requests. The instance must not be used afterwards. */
    public fun close() {
        scope.cancel()
    }

    /**
     * Protocol v2: [intentToken] is the opaque string your backend got from `POST /v2/intents`.
     * Runs challenge -> collect -> identify and returns an opaque attestation for your backend.
     * Never throws except on cancellation.
     */
    public suspend fun identify(intentToken: String): FpIdentifyResult = identify(intentToken, FpEventOptions())

    /**
     * As [identify] with an intent token, also storing [options] (`linkedId`, `tags`) on the event; the success
     * carries the `eventId`. Invalid options fail before any request.
     */
    public suspend fun identify(intentToken: String, options: FpEventOptions): FpIdentifyResult = withContext(Dispatchers.IO) {
        try {
            runV2(intentToken, options)
        } catch (_: IOException) {
            FpIdentifyResult.Failure("network", 0)
        }
    }

    /** Callback variant of [identify] with an intent token; [callback] is invoked on the main thread. */
    public fun identify(intentToken: String, callback: FpIdentifyCallback) {
        identify(intentToken, FpEventOptions(), callback)
    }

    /** Callback variant of [identify] with an intent token and [options]; [callback] is invoked on the main thread. */
    public fun identify(intentToken: String, options: FpEventOptions, callback: FpIdentifyCallback) {
        scope.launch {
            val result = identify(intentToken, options)
            mainHandler.post { callback.onResult(result) }
        }
    }

    private suspend fun runV2(intentToken: String, options: FpEventOptions): FpIdentifyResult {
        if (intentToken.isBlank()) return FpIdentifyResult.Failure("bad_intent_token", 0)
        val fields = EventFields.validate(options.linkedId, options.tags)
        if (fields is EventFields.Invalid) return FpIdentifyResult.Failure(fields.reason, 0)
        val response = api.challengeV2(intentToken, config.powDifficulty)
        val challenge = if (response.status == 200) ResponseParser.parseChallengeV2(response.body) else null
        if (challenge == null) {
            val reason = ResponseParser.parseErrorV2(response.body) ?: "challenge_failed"
            return FpIdentifyResult.Failure(reason, response.status)
        }

        val components = ComponentRules.build(DeviceSignals.read(appContext))
        if (ComponentRules.validate(components).isNotEmpty()) return FpIdentifyResult.Failure("no_device_id", 0)

        val agentVersion = "android-${BuildConfig.SDK_VERSION}"
        val bytes = try {
            Jcs.identifyBytes("android", agentVersion, challenge, components.map { JcsComponent(it.key, it.value) })
        } catch (_: IllegalArgumentException) {
            return FpIdentifyResult.Failure("bad_canonical", 0)
        }
        val pow = config.powDifficulty?.let { bits -> solvePow(challenge, bits) }
        val token = integrity?.token(Jcs.requestHashHex(bytes))

        val body = RequestBody.buildV2(intentToken, challenge, components, agentVersion, pow, token, fields as EventFields.Ok)
        val answer = api.identifyV2(body)
        return ResponseParser.parseIdentifyV2(answer.body, answer.status)
    }

    private suspend fun run(options: FpEventOptions): FpResult {
        val sealKey = config.sealKey ?: return FpResult.Failure("seal_key_missing", 0)
        val fields = EventFields.validate(options.linkedId, options.tags)
        if (fields is EventFields.Invalid) return FpResult.Failure(fields.reason, 0)
        val challenge = api.challenge(config.powDifficulty)
        val nonce = if (challenge.status == 200) ResponseParser.parseNonce(challenge.body) else null
        if (nonce == null) {
            return failureFrom(challenge, fallback = "challenge_failed")
        }

        val components = ComponentRules.build(DeviceSignals.read(appContext))
        if (ComponentRules.validate(components).isNotEmpty()) {
            // Without a usable device id the server would answer bad_request anyway.
            return FpResult.Failure("no_device_id", 0)
        }

        val canonical = Canonical.payload(nonce, components)
        val sig = Canonical.seal(sealKey, canonical)
        val pow = config.powDifficulty?.let { bits -> solvePow(nonce, bits) }
        val token = integrity?.token(Canonical.requestHash(canonical))

        val body = RequestBody.build(nonce, sig, components, "android-${BuildConfig.SDK_VERSION}", pow, token, fields as EventFields.Ok)
        val response = api.identify(body)
        return ResponseParser.parseIdentify(response.body, response.status)
    }

    private suspend fun solvePow(nonce: String, bits: Int): String? = withContext(Dispatchers.Default) {
        val job = currentCoroutineContext()[Job]
        val solution = Pow.solve(nonce, bits) { job?.isActive != false }
        currentCoroutineContext().ensureActive()
        solution
    }

    private fun failureFrom(response: ApiClient.Response, fallback: String): FpResult {
        val parsed = ResponseParser.parseIdentify(response.body, response.status)
        val reason = (parsed as? FpResult.Failure)?.reason
        return FpResult.Failure(if (reason == null || reason == "bad_response") fallback else reason, response.status)
    }
}
