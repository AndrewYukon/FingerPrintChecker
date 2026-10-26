package com.fpchecker.integrity

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch

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

    /** Blocks until [release] is called, so it can never finish inside a test deadline, however slow the host is. */
    private class Blocked(override val code: String) : Probe {
        private val latch = CountDownLatch(1)
        fun release() = latch.countDown()
        override fun run(env: ProbeEnv): ProbeResult {
            latch.await()
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

    /** Generous deadline: the quick probes finish long before it even on a cold, loaded host. */
    private val deadlineMs = 1_500L

    private suspend fun warmUp() {
        IntegrityProbes.collect(FakeProbeEnv(), listOf(Quick("root", ProbeResult.CLEAN)), 5_000)
    }

    @Test
    fun slowProbeInTheMiddleDoesNotCostLaterResults() = runBlocking {
        warmUp()
        val blocked = Blocked("mitm")
        try {
            val probes = listOf(
                Quick("root", ProbeResult.CLEAN), blocked, Quick("vpn", ProbeResult.FIRED),
                Quick("mock_location", ProbeResult.CLEAN), Quick("clone", ProbeResult.FIRED),
            )
            val parts = IntegrityProbes.collect(FakeProbeEnv(), probes, deadlineMs).split(":")
            val unavailable = parts[2].split(",")
            assertEquals(listOf("vpn", "clone"), parts[1].split(","))
            assertTrue("mitm" in unavailable)
            assertTrue("root" !in unavailable && "vpn" !in unavailable && "mock_location" !in unavailable && "clone" !in unavailable)
        } finally {
            blocked.release()
        }
    }

    @Test
    fun aProbeThrowingCancellationIsUnavailableNotPropagated() = runBlocking {
        val encoded = IntegrityProbes.collect(FakeProbeEnv(), listOf(Quick("root", ProbeResult.FIRED), Cancelling()), 5_000)
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
    fun blockedProbeBecomesUnavailableAndDoesNotHoldTheCaller() = runBlocking {
        warmUp()
        val blocked = Blocked("hook")
        try {
            // The probe cannot finish until released after the call, so a collector that waited on it would hang;
            // the outer timeout turns that into a clear failure instead.
            val start = System.nanoTime()
            val encoded = withTimeoutOrNull(10_000) {
                IntegrityProbes.collect(FakeProbeEnv(), listOf(Quick("root", ProbeResult.FIRED), blocked), deadlineMs)
            }
            val elapsedMs = (System.nanoTime() - start) / 1_000_000
            assertNotNull("collect was held by the blocked probe", encoded)
            assertTrue("took ${elapsedMs}ms", elapsedMs < 10_000)
            assertTrue(encoded!!.startsWith("1:root:"))
            assertTrue("hook" in encoded.split(":")[2].split(","))
        } finally {
            blocked.release()
        }
    }

    @Test
    fun stackOverflowInAProbeIsUnavailable() = runBlocking {
        val overflow = object : Probe {
            override val code = "hook"
            override fun run(env: ProbeEnv): ProbeResult = throw StackOverflowError()
        }
        val encoded = IntegrityProbes.collect(FakeProbeEnv(), listOf(Quick("root", ProbeResult.FIRED), overflow), 5_000)
        assertEquals("1:root:${IntegrityProbes.CODES.filter { it != "root" }.joinToString(",")}", encoded)
    }

    @Test
    fun stackOverflowInOneCheckKeepsOtherEvidence() {
        val env = object : FakeProbeEnv(frida = true) {
            override fun fileContainsAny(path: String, markers: List<String>): Boolean = throw StackOverflowError()
        }
        assertEquals(ProbeResult.FIRED, HookProbe.run(env))
    }
}
