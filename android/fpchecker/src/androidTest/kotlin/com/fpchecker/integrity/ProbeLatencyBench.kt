package com.fpchecker.integrity

import android.os.Bundle
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Measures each integrity probe on a real device (M22). Not a pass/fail gate on speed: it reports, so a slow
 * device shows up as numbers instead of a flaky red. Run with `./gradlew :fpchecker:connectedDebugAndroidTest`;
 * results land in the instrumentation status (and logcat tag FpcProbeLatency).
 *
 * The first pass runs in a fresh test process, so it includes the cold costs the 300 ms deadline has to absorb
 * (CA store load, class lookups); later passes are warm.
 */
@RunWith(AndroidJUnit4::class)
public class ProbeLatencyBench {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val env = AndroidProbeEnv(instrumentation.targetContext)

    @Test
    public fun perProbeLatency() {
        val cold = ALL_PROBES.associate { it.code to timeMs { it.run(env) } }
        val warm = ALL_PROBES.associate { probe -> probe.code to List(WARM_RUNS) { timeMs { probe.run(env) } }.sorted() }
        val collectWall = List(WARM_RUNS) { timeMs { runBlocking { IntegrityProbes.collect(env) } } }.sorted()

        val lines = ALL_PROBES.map { probe ->
            val w = warm.getValue(probe.code)
            "%-14s cold %7.1f  warm p50 %6.1f  p95 %6.1f  max %6.1f".format(
                probe.code, cold.getValue(probe.code), w[w.size / 2], w[(w.size * 95) / 100], w.last(),
            )
        } + "%-14s       p50 %6.1f  p95 %6.1f  max %6.1f".format(
            "collect()", collectWall[collectWall.size / 2], collectWall[(collectWall.size * 95) / 100], collectWall.last(),
        )
        lines.forEach { android.util.Log.i(TAG, it) }
        instrumentation.sendStatus(0, Bundle().apply { putString("stream", lines.joinToString("\n", postfix = "\n")) })
        assertEquals(IntegrityProbes.CODES.size, cold.size)
    }

    private inline fun timeMs(block: () -> Unit): Double {
        val start = SystemClock.elapsedRealtimeNanos()
        block()
        return (SystemClock.elapsedRealtimeNanos() - start) / 1_000_000.0
    }

    private companion object {
        const val TAG = "FpcProbeLatency"
        const val WARM_RUNS = 40
    }
}
