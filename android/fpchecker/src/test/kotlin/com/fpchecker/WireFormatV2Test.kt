package com.fpchecker

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WireFormatV2Test {
    private val comps = listOf(Component("android.id", "1a2b3c4d5e6f7081"))

    @Test
    fun bodyHasIntentAndChallengeButNoSig() {
        val body = JSONObject(RequestBody.buildV2("fpi1.x", "v4.c", comps, "android-0.2.0", "77", "tok"))
        assertEquals(2, body.getInt("protocolVersion"))
        assertEquals("android", body.getString("platform"))
        assertEquals("fpi1.x", body.getString("intentToken"))
        assertEquals("v4.c", body.getString("challenge"))
        assertEquals("android-0.2.0", body.getString("agentVersion"))
        assertTrue(body.get("pow") is String)
        assertEquals("play_integrity", body.getJSONObject("proof").getString("type"))
        assertFalse(body.has("sig"))
        assertFalse(body.has("nonce"))
    }

    @Test
    fun optionalFieldsAbsentWhenNotUsed() {
        val body = JSONObject(RequestBody.buildV2("i", "c", comps, "v", null, null))
        assertFalse(body.has("pow"))
        assertFalse(body.has("proof"))
    }

    @Test
    fun parsesMinimalSuccess() {
        val json = """{"ok":true,"protocolVersion":2,"attestation":"fpa1.abc","expiresIn":600,"proofStatus":"checked"}"""
        val r = ResponseParser.parseIdentifyV2(json, 200) as FpIdentifyResult.Success
        assertEquals("fpa1.abc", r.attestation)
        assertEquals(600, r.expiresIn)
        assertEquals("checked", r.proofStatus)
        assertNull(r.visitorId)
        assertNull(r.trustScore)
        assertNull(r.isNew)
        assertEquals(emptyList<String>(), r.trustDeductions)
        assertEquals(json, r.rawJson)
    }

    @Test
    fun parsesScoreDetails() {
        val json = """{"ok":true,"protocolVersion":2,"attestation":"fpa1.abc","visitorId":"a4_x","trustScore":55,
            "identityConfidence":90,"isNew":false,"trustDeductions":["d"],"shadowDeductions":["s",1],"rulesVersion":"n2"}"""
        val r = ResponseParser.parseIdentifyV2(json, 200) as FpIdentifyResult.Success
        assertEquals("a4_x", r.visitorId)
        assertEquals(55, r.trustScore)
        assertEquals(90, r.identityConfidence)
        assertEquals(false, r.isNew)
        assertEquals(listOf("d"), r.trustDeductions)
        assertEquals(listOf("s"), r.shadowDeductions)
        assertEquals("n2", r.rulesVersion)
    }

    @Test
    fun successWithoutAttestationIsFailure() {
        val bad = FpIdentifyResult.Failure("bad_response", 200)
        assertEquals(bad, ResponseParser.parseIdentifyV2("""{"ok":true,"protocolVersion":2}""", 200))
        assertEquals(bad, ResponseParser.parseIdentifyV2("""{"ok":true,"attestation":""}""", 200))
        assertEquals(bad, ResponseParser.parseIdentifyV2("""{"ok":true,"attestation":null}""", 200))
        assertEquals(bad, ResponseParser.parseIdentifyV2("""{"ok":true,"attestation":{"a":1}}""", 200))
        assertEquals(bad, ResponseParser.parseIdentifyV2("<html>", 200))
    }

    @Test
    fun parsesServerFailure() {
        val r = ResponseParser.parseIdentifyV2("""{"ok":false,"protocolVersion":2,"reason":"bad_intent"}""", 400)
        assertEquals(FpIdentifyResult.Failure("bad_intent", 400), r)
    }

    @Test
    fun parsesChallenge() {
        assertEquals("v4.x", ResponseParser.parseChallengeV2("""{"ok":true,"protocolVersion":2,"challenge":"v4.x","expiresIn":300}"""))
        assertNull(ResponseParser.parseChallengeV2("""{"ok":false,"error":"bad_intent"}"""))
        assertNull(ResponseParser.parseChallengeV2("""{"ok":true}"""))
        assertNull(ResponseParser.parseChallengeV2("nope"))
        assertEquals("bad_intent", ResponseParser.parseErrorV2("""{"ok":false,"error":"bad_intent"}"""))
        assertNull(ResponseParser.parseErrorV2("nope"))
    }

    @Test
    fun configWithoutSealKeyIsValid() {
        val c = FpCheckerConfig(publishableKey = "pk")
        assertNull(c.sealKey)
    }
}
