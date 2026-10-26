package com.fpchecker.integrity

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ConcurrentHashMap

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
     * Probes run in parallel on the IO pool and share one deadline. We wait once for all of them, then read
     * whatever finished: a probe that threw, or had not finished at the deadline, is UNAVAILABLE, and a slow probe
     * never costs the results of the others. The probe scope is deliberately not joined: a blocked read must not
     * hold the caller.
     */
    suspend fun collect(env: ProbeEnv, probes: List<Probe>, timeoutMs: Long): String {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val finished = ConcurrentHashMap<String, ProbeResult>()
            val jobs = probes.map { probe -> scope.launch { finished[probe.code] = runSafely(probe, env) } }
            withTimeoutOrNull(timeoutMs) { jobs.joinAll() }
            return encode(HashMap(finished))
        } finally {
            scope.cancel()
        }
    }

    private fun runSafely(probe: Probe, env: ProbeEnv): ProbeResult = try {
        probe.run(env)
    } catch (e: OutOfMemoryError) {
        throw e
    } catch (_: Throwable) {
        // Includes StackOverflowError and CancellationException thrown by a probe: that is the probe failing, not the caller cancelling.
        ProbeResult.UNAVAILABLE
    }
}
