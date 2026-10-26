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

    @Test
    fun slowProbeTimesOutToUnavailableWithinBudget() = runBlocking {
        val probes = listOf(Quick("root", ProbeResult.FIRED), Slow())
        // Warm the dispatcher and timer threads: cold class loading is not part of the budget under test.
        IntegrityProbes.collect(FakeProbeEnv(), listOf(Quick("root", ProbeResult.CLEAN)), 200)
        val start = System.nanoTime()
        val encoded = IntegrityProbes.collect(FakeProbeEnv(), probes, 200)
        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        assertTrue("took ${elapsedMs}ms", elapsedMs < 250)
        // Codes not run at all are reported unavailable too, so only the relevant parts are asserted.
        assertTrue(encoded.startsWith("1:root:"))
        assertTrue(encoded.split(":")[2].split(",").contains("hook"))
    }

    @Test
    fun setupDayConvertsMillisToUtcDays() {
        assertEquals(20_000, SetupDay.dayOf(20_000L * 86_400_000L + 5_000))
        assertEquals(null, SetupDay.dayOf(0))
        assertEquals(null, SetupDay.dayOf(-1))
        assertEquals(null, SetupDay.dayOf(1_000_000L * 86_400_000L))
    }
}
