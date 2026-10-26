package com.fpchecker.integrity

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.withTimeoutOrNull

/** Encodes the `android.integrity` component: `<version>:<fired csv>:<unavailable csv>`, codes in [CODES] order. */
internal object IntegrityProbes {
    const val VERSION = 1
    val CODES: List<String> = listOf("root", "hook", "emulator", "debugger", "devopts", "mitm", "vpn", "mock_location", "clone")

    /** A code missing from [results] is reported unavailable, never clean. */
    fun encode(results: Map<String, ProbeResult>): String {
        val fired = CODES.filter { results[it] == ProbeResult.FIRED }
        val unavailable = CODES.filter { (results[it] ?: ProbeResult.UNAVAILABLE) == ProbeResult.UNAVAILABLE }
        return "$VERSION:${fired.joinToString(",")}:${unavailable.joinToString(",")}"
    }

    /** What the SDK sends when probes are switched off: every code unavailable, nothing fired. */
    fun disabled(): String = encode(CODES.associateWith { ProbeResult.UNAVAILABLE })

    suspend fun collect(env: ProbeEnv, timeoutMs: Long = 300): String = collect(env, ALL_PROBES, timeoutMs)

    /**
     * Probes run in parallel on the IO pool inside one shared deadline. A probe that throws or misses the
     * deadline is UNAVAILABLE. The probe scope is deliberately not joined: a blocked read must not hold the caller.
     */
    suspend fun collect(env: ProbeEnv, probes: List<Probe>, timeoutMs: Long): String {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val deadline = System.nanoTime() + timeoutMs * 1_000_000
            val running: List<Pair<Probe, Deferred<ProbeResult>>> = probes.map { probe ->
                probe to scope.async { runSafely(probe, env) }
            }
            val results = HashMap<String, ProbeResult>()
            for ((probe, job) in running) {
                val remainingMs = ((deadline - System.nanoTime()) / 1_000_000).coerceAtLeast(0)
                results[probe.code] = withTimeoutOrNull(remainingMs) { job.await() } ?: ProbeResult.UNAVAILABLE
            }
            return encode(results)
        } finally {
            scope.cancel()
        }
    }

    private fun runSafely(probe: Probe, env: ProbeEnv): ProbeResult = try {
        probe.run(env)
    } catch (e: CancellationException) {
        throw e
    } catch (_: Throwable) {
        ProbeResult.UNAVAILABLE
    }
}
