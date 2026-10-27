package com.fpchecker.reactnative

import com.fpchecker.FpEventOptions
import com.fpchecker.FpIdentifyResult
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

class BridgeTest {
    private val okResult = FpIdentifyResult.Success(attestation = "att", rawJson = "{}", visitorId = "v1")

    private class FakeIdentifier(
        val onIdentify: suspend (String, FpEventOptions) -> FpIdentifyResult,
    ) : Identifier {
        var closed = false
        override suspend fun identify(intentToken: String, options: FpEventOptions) = onIdentify(intentToken, options)
        override fun close() { closed = true }
    }

    private fun args(
        config: Map<String, Any?> = mapOf("publishableKey" to "pk_test"),
        extra: Map<String, Any?> = mapOf("intentToken" to "tok"),
    ): Map<String, Any?> = mapOf("config" to config) + extra

    // --- replyOf / failureReply ---------------------------------------------------------------

    @Test fun replyOfSuccessFillsF2AndKeepsListsNonNull() {
        val reply = replyOf(
            FpIdentifyResult.Success(
                attestation = "att", expiresIn = 60, proofStatus = "checked", visitorId = "v1",
                trustScore = 90, identityConfidence = 80, isNew = true,
                trustDeductions = listOf("a"), shadowDeductions = emptyList(),
                rulesVersion = "r1", rawJson = "{\"x\":1}", eventId = "e1", sealedResult = "fpsr1.x",
            ),
        )
        assertEquals(true, reply["ok"])
        assertEquals("v1", reply["visitorId"])
        assertEquals("att", reply["attestation"])
        assertEquals("e1", reply["eventId"])
        assertEquals(90, reply["trustScore"])
        assertEquals(true, reply["isNew"])
        assertEquals(listOf("a"), reply["trustDeductions"])
        assertEquals(emptyList<String>(), reply["shadowDeductions"])
        assertEquals("{\"x\":1}", reply["rawJson"])
        assertEquals("fpsr1.x", reply["sealedResult"])
    }

    @Test fun replyOfSuccessWithoutOptionalsOmitsThemButListsAndRawJsonPresent() {
        val reply = replyOf(okResult)
        assertNull(reply["eventId"])
        assertNull(reply["trustScore"])
        assertEquals(emptyList<String>(), reply["trustDeductions"])
        assertEquals(emptyList<String>(), reply["shadowDeductions"])
        assertEquals("{}", reply["rawJson"])
    }

    @Test fun replyOfFailure() {
        assertEquals(
            mapOf("ok" to false, "reason" to "network", "httpStatus" to 0),
            replyOf(FpIdentifyResult.Failure("network", 0)),
        )
    }

    @Test fun failureReplyShape() {
        assertEquals(mapOf("ok" to false, "reason" to "bad_config", "httpStatus" to 0), failureReply("bad_config", 0))
    }

    // --- configFrom ----------------------------------------------------------------------------

    @Test fun configFromFullF1Map() {
        val c = configFrom(
            mapOf(
                "publishableKey" to "pk_x", "baseUrl" to "https://api.example.com", "powDifficulty" to 12.0,
                "integrityProbes" to false, "cloudProjectNumber" to 123456.0, "integrityTimeoutMillis" to 2500.0,
                "useAppAttest" to true, "useDeviceCheck" to true,
            ),
        )
        assertEquals("pk_x", c.publishableKey)
        assertEquals("https://api.example.com", c.baseUrl)
        assertEquals(12, c.powDifficulty)
        assertFalse(c.integrityProbes)
        assertEquals(123456L, c.cloudProjectNumber)
        assertEquals(2500L, c.integrityTimeoutMillis)
        assertNull(c.sealKey)
    }

    @Test fun configFromDefaults() {
        val c = configFrom(mapOf("publishableKey" to "pk_x"))
        assertEquals("https://api.fpchecker.com", c.baseUrl)
        assertTrue(c.integrityProbes)
        assertNull(c.powDifficulty)
    }

    @Test fun configFromIgnoresSealKey() {
        assertNull(configFrom(mapOf("publishableKey" to "pk_x", "sealKey" to "secret")).sealKey)
    }

    @Test fun configFromRejectsHttpOnNonLoopback() {
        assertThrows(IllegalArgumentException::class.java) {
            configFrom(mapOf("publishableKey" to "pk_x", "baseUrl" to "http://api.example.com"))
        }
    }

    @Test fun configFromAllowsHttpOnLoopback() {
        for (u in listOf("http://localhost:8080", "http://127.0.0.1:3000", "http://[::1]:3000")) {
            assertEquals(u, configFrom(mapOf("publishableKey" to "pk_x", "baseUrl" to u)).baseUrl)
        }
    }

    @Test fun configFromRejectsLoopbackLookalikeHost() {
        assertThrows(IllegalArgumentException::class.java) {
            configFrom(mapOf("publishableKey" to "pk_x", "baseUrl" to "http://localhost.evil.com"))
        }
    }

    @Test fun configFromRejectsEmptyOrMissingPk() {
        assertThrows(IllegalArgumentException::class.java) { configFrom(mapOf("publishableKey" to "")) }
        assertThrows(IllegalArgumentException::class.java) { configFrom(emptyMap()) }
        assertThrows(IllegalArgumentException::class.java) { configFrom(mapOf("publishableKey" to 5.0)) }
    }

    @Test fun configFromRejectsWrongTypes() {
        assertThrows(IllegalArgumentException::class.java) {
            configFrom(mapOf("publishableKey" to "pk", "powDifficulty" to "high"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            configFrom(mapOf("publishableKey" to "pk", "powDifficulty" to 12.5))
        }
    }

    // --- handler -------------------------------------------------------------------------------

    @Test fun handlerSuccessPassesTokenLinkedIdAndTags() = runBlocking {
        var seen: Pair<String, FpEventOptions>? = null
        val h = IdentifyHandler { FakeIdentifier { t, o -> seen = t to o; okResult } }
        val reply = h.handle(args(extra = mapOf("intentToken" to "tok", "linkedId" to "L1", "tags" to mapOf("n" to 2.0, "s" to "x"))))
        assertEquals(true, reply["ok"])
        assertEquals("tok", seen!!.first)
        assertEquals("L1", seen!!.second.linkedId)
        assertEquals(mapOf("n" to 2L, "s" to "x"), seen!!.second.tags)
    }

    @Test fun handlerForcedThrowMapsToBridgeError() = runBlocking {
        val h = IdentifyHandler { FakeIdentifier { _, _ -> throw IllegalStateException("keystore") } }
        assertEquals(failureReply("bridge_error", 0), h.handle(args()))
    }

    @Test fun handlerForcedThrowOfIllegalArgumentFromIdentifyIsBridgeNotBadConfig() = runBlocking {
        val h = IdentifyHandler { FakeIdentifier { _, _ -> throw IllegalArgumentException("deep") } }
        assertEquals(failureReply("bridge_error", 0), h.handle(args()))
    }

    @Test fun handlerFactoryThrowMapsToBridgeError() = runBlocking {
        val h = IdentifyHandler { throw java.security.KeyStoreException("boom") }
        assertEquals(failureReply("bridge_error", 0), h.handle(args()))
    }

    @Test fun handlerBadConfigMapsToBadConfig() = runBlocking {
        val h = IdentifyHandler { FakeIdentifier { _, _ -> okResult } }
        assertEquals(failureReply("bad_config", 0), h.handle(args(config = mapOf("publishableKey" to ""))))
        assertEquals(
            failureReply("bad_config", 0),
            h.handle(args(config = mapOf("publishableKey" to "pk", "baseUrl" to "http://example.com"))),
        )
        assertEquals(failureReply("bad_config", 0), h.handle(mapOf("intentToken" to "t")))
    }

    @Test fun handlerBadIntentToken() = runBlocking {
        val h = IdentifyHandler { FakeIdentifier { _, _ -> okResult } }
        assertEquals(failureReply("bad_intent_token", 0), h.handle(args(extra = emptyMap())))
        assertEquals(failureReply("bad_intent_token", 0), h.handle(args(extra = mapOf("intentToken" to ""))))
    }

    @Test fun handlerPassesNativeFailureThrough() = runBlocking {
        val h = IdentifyHandler { FakeIdentifier { _, _ -> FpIdentifyResult.Failure("bad_intent", 400) } }
        assertEquals(mapOf("ok" to false, "reason" to "bad_intent", "httpStatus" to 400), h.handle(args()))
    }

    @Test fun concurrentSameConfigUsesOneInstanceAndBothResolve() = runBlocking {
        val created = AtomicInteger()
        val gate = CompletableDeferred<Unit>()
        val h = IdentifyHandler {
            created.incrementAndGet()
            FakeIdentifier { _, _ -> gate.await(); okResult }
        }
        // Same config, different key order must still map to one instance.
        val a = async { h.handle(args(config = linkedMapOf("publishableKey" to "pk", "powDifficulty" to 10.0))) }
        val b = async { h.handle(args(config = linkedMapOf("powDifficulty" to 10.0, "publishableKey" to "pk"))) }
        gate.complete(Unit)
        val replies = listOf(a, b).awaitAll()
        assertEquals(1, created.get())
        assertTrue(replies.all { it["ok"] == true })
    }

    @Test fun differentConfigsGetDifferentInstancesAndCloseClosesAll() = runBlocking {
        val made = mutableListOf<FakeIdentifier>()
        val h = IdentifyHandler { FakeIdentifier { _, _ -> okResult }.also(made::add) }
        h.handle(args(config = mapOf("publishableKey" to "pk1")))
        h.handle(args(config = mapOf("publishableKey" to "pk2")))
        assertEquals(2, made.size)
        h.close()
        assertTrue(made.all { it.closed })
    }
}
