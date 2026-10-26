package com.fpchecker.integrity

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IntegrityProbesTest {
    private val all = "root,hook,emulator,debugger,devopts,mitm,vpn,mock_location,clone"

    @Test
    fun codesAreInWireOrder() = assertEquals(all, IntegrityProbes.CODES.joinToString(","))

    @Test
    fun encodeFollowsCodeOrder() {
        val results = IntegrityProbes.CODES.associateWith { ProbeResult.CLEAN } +
            mapOf("root" to ProbeResult.FIRED, "mock_location" to ProbeResult.UNAVAILABLE)
        assertEquals("1:root:mock_location", IntegrityProbes.encode(results))
    }

    @Test
    fun encodeOrdersByCodesNotInsertion() {
        val results = linkedMapOf(
            "clone" to ProbeResult.FIRED, "hook" to ProbeResult.FIRED, "vpn" to ProbeResult.UNAVAILABLE, "mitm" to ProbeResult.UNAVAILABLE,
        )
        val encoded = IntegrityProbes.encode(IntegrityProbes.CODES.associateWith { ProbeResult.CLEAN } + results)
        assertEquals("1:hook,clone:mitm,vpn", encoded)
    }

    @Test
    fun missingCodesAreUnavailableNotClean() {
        assertEquals("1::$all", IntegrityProbes.encode(emptyMap()))
    }

    @Test
    fun allCleanEncodesEmptyLists() {
        assertEquals("1::", IntegrityProbes.encode(IntegrityProbes.CODES.associateWith { ProbeResult.CLEAN }))
    }

    @Test
    fun disabledReportsEverythingUnavailable() = assertEquals("1::$all", IntegrityProbes.disabled())

    @Test
    fun encodedValuesPassTheWireRegex() {
        val regex = Regex("^[0-9]{1,3}:([a-z_]+(,[a-z_]+)*)?:([a-z_]+(,[a-z_]+)*)?$")
        assertTrue(regex.matches(IntegrityProbes.disabled()))
        assertTrue(regex.matches(IntegrityProbes.encode(IntegrityProbes.CODES.associateWith { ProbeResult.FIRED })))
    }

    @Test
    fun collectReportsFiredAndCleanFromRealProbes() = runBlocking {
        val env = FakeProbeEnv(files = setOf("/system/xbin/su"), vpn = null, mock = null)
        assertEquals("1:root:vpn,mock_location", IntegrityProbes.collect(env))
    }

    @Test
    fun collectOnAThrowingEnvIsAllUnavailableAndNeverThrows() = runBlocking {
        assertEquals("1::$all", IntegrityProbes.collect(ThrowingProbeEnv()))
    }

    private class Slow : Probe {
        override val code = "hook"
        override fun run(env: ProbeEnv): ProbeResult {
            Thread.sleep(2_000)
            return ProbeResult.FIRED
        }
    }

    private class Quick(override val code: String, private val result: ProbeResult) : Probe {
        override fun run(env: ProbeEnv) = result
    }

    private class Cancelling : Probe {
        override val code = "mitm"
        override fun run(env: ProbeEnv): ProbeResult = throw kotlinx.coroutines.CancellationException("probe bug")
    }

    @Test
    fun slowProbeInTheMiddleDoesNotCostLaterResults() = runBlocking {
        val slowMitm = object : Probe {
            override val code = "mitm"
            override fun run(env: ProbeEnv): ProbeResult {
                Thread.sleep(2_000)
                return ProbeResult.FIRED
            }
        }
        val probes = listOf(
            Quick("root", ProbeResult.CLEAN), slowMitm, Quick("vpn", ProbeResult.FIRED),
            Quick("mock_location", ProbeResult.CLEAN), Quick("clone", ProbeResult.FIRED),
        )
        val parts = IntegrityProbes.collect(FakeProbeEnv(), probes, 200).split(":")
        val fired = parts[1].split(",")
        val unavailable = parts[2].split(",")
        assertEquals(listOf("vpn", "clone"), fired)
        assertTrue("mitm" in unavailable)
        assertTrue("root" !in unavailable && "vpn" !in unavailable && "mock_location" !in unavailable && "clone" !in unavailable)
    }

    @Test
    fun aProbeThrowingCancellationIsUnavailableNotPropagated() = runBlocking {
        val encoded = IntegrityProbes.collect(FakeProbeEnv(), listOf(Quick("root", ProbeResult.FIRED), Cancelling()), 200)
        assertTrue(encoded.startsWith("1:root:"))
        assertTrue("mitm" in encoded.split(":")[2].split(","))
    }

    @Test
    fun linkageErrorInOneCheckKeepsEvidenceFromAnother() {
        val env = object : FakeProbeEnv(files = setOf("/system/xbin/su")) {
            override fun classExists(name: String): Boolean = throw NoClassDefFoundError(name)
        }
        assertEquals(ProbeResult.FIRED, HookProbe.run(object : FakeProbeEnv(frida = true) {
            override fun classExists(name: String): Boolean = throw NoClassDefFoundError(name)
        }))
        assertEquals(ProbeResult.UNAVAILABLE, HookProbe.run(env))
    }

    @Test
    fun slowProbeTimesOutToUnavailableWithinBudget() = runBlocking {
        val probes = listOf(Quick("root", ProbeResult.FIRED), Slow())
        // Warm the dispatcher and timer threads: cold class loading is not part of the budget under test.
        IntegrityProbes.collect(FakeProbeEnv(), listOf(Quick("root", ProbeResult.CLEAN)), 200)
        // Best of three: the shared CI host can stall one run, but a probe that blocks the caller would stall all three.
        var best = Long.MAX_VALUE
        var encoded = ""
        repeat(3) {
            val start = System.nanoTime()
            encoded = IntegrityProbes.collect(FakeProbeEnv(), probes, 200)
            best = minOf(best, (System.nanoTime() - start) / 1_000_000)
        }
        assertTrue("best of 3 took ${best}ms", best < 250)
        // Codes not run at all are reported unavailable too, so only the relevant parts are asserted.
        assertTrue(encoded.startsWith("1:root:"))
        assertTrue(encoded.split(":")[2].split(",").contains("hook"))
    }
}
