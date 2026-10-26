package com.fpchecker.integrity

/** Outcome of one probe. UNAVAILABLE means "could not run" (no permission, timeout, exception), never "clean". */
internal enum class ProbeResult { FIRED, CLEAN, UNAVAILABLE }

internal interface Probe {
    /** Wire code, one of [IntegrityProbes.CODES]. */
    val code: String

    /** May throw; the collector turns any exception into [ProbeResult.UNAVAILABLE]. */
    fun run(env: ProbeEnv): ProbeResult
}
