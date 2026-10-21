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
 * [identify]. The seal key is embedded in your app and therefore only raises the bar for forged
 * requests; trust decisions belong to the attestation verified by your backend.
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
    public suspend fun identify(): FpResult = withContext(Dispatchers.IO) {
        try {
            run()
        } catch (_: IOException) {
            FpResult.Failure("network", 0)
        }
    }

    /** Callback variant for Java callers; [callback] is invoked on the main thread. */
    public fun identify(callback: FpCallback) {
        scope.launch {
            val result = identify()
            mainHandler.post { callback.onResult(result) }
        }
    }

    /** Cancels in-flight callback-style requests. The instance must not be used afterwards. */
    public fun close() {
        scope.cancel()
    }

    private suspend fun run(): FpResult {
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
        val sig = Canonical.seal(config.sealKey, canonical)
        val pow = config.powDifficulty?.let { bits -> solvePow(nonce, bits) }
        val token = integrity?.token(Canonical.requestHash(canonical))

        val body = RequestBody.build(nonce, sig, components, "android-${BuildConfig.SDK_VERSION}", pow, token)
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
