package com.fpchecker

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WireFormatTest {
    private val comps = listOf(Component("android.id", "1a2b3c4d5e6f7081"))

    @Test
    fun powIsSentAsJsonString() {
        val body = JSONObject(RequestBody.build("n", "s", comps, "android-0.1.0", "1904", null))
        assertTrue(body.get("pow") is String)
        assertEquals("1904", body.getString("pow"))
    }

    @Test
    fun optionalFieldsAreAbsentWhenNotUsed() {
        val body = JSONObject(RequestBody.build("n", "s", comps, "android-0.1.0", null, null))
        assertFalse(body.has("pow"))
        assertFalse(body.has("proof"))
        assertEquals("android", body.getString("platform"))
        assertEquals("android-0.1.0", body.getString("agentVersion"))
        assertEquals("android.id", body.getJSONArray("components").getJSONObject(0).getString("key"))
    }

    @Test
    fun proofCarriesPlayIntegrityToken() {
        val body = JSONObject(RequestBody.build("n", "s", comps, "v", null, "tok"))
        val proof = body.getJSONObject("proof")
        assertEquals("play_integrity", proof.getString("type"))
        assertEquals("tok", proof.getString("token"))
    }

    @Test
    fun parsesSuccess() {
        val json = """{"ok":true,"platform":"android","visitorId":"a4_abc","confidence":100,"identityConfidence":100,
            "trustScore":55,"trustDeductions":["native_unattested"],"shadowDeductions":["play_integrity_unavailable",7],
            "rulesVersion":"n2","isNew":true,"attestation":"tok.en","proofStatus":"unavailable"}"""
        val r = ResponseParser.parseIdentify(json, 200) as FpResult.Success
        assertEquals("a4_abc", r.visitorId)
        assertEquals(55, r.trustScore)
        assertEquals(100, r.identityConfidence)
        assertTrue(r.isNew)
        assertEquals("tok.en", r.attestation)
        assertEquals(listOf("native_unattested"), r.trustDeductions)
        assertEquals(listOf("play_integrity_unavailable"), r.shadowDeductions)
        assertEquals("unavailable", r.proofStatus)
        assertEquals(json, r.rawJson)
    }

    @Test
    fun sealedAttestationAndHiddenScoresParseToNullNotZero() {
        val r = ResponseParser.parseIdentify("""{"ok":true,"visitorId":"a4_abc","isNew":true,"attestation":{"token":"fpa1.x"}}""", 200) as FpResult.Success
        assertNull(r.trustScore)
        assertNull(r.identityConfidence)
        assertEquals("""{"token":"fpa1.x"}""", r.attestation)
    }

    @Test
    fun scoreZeroIsKeptAsZero() {
        val r = ResponseParser.parseIdentify("""{"ok":true,"visitorId":"a4_abc","trustScore":0,"identityConfidence":0}""", 200) as FpResult.Success
        assertEquals(0, r.trustScore)
        assertEquals(0, r.identityConfidence)
    }

    @Test
    fun olderServerWithoutShadowOrProofStatus() {
        val r = ResponseParser.parseIdentify("""{"ok":true,"visitorId":"a4_abc","trustScore":55}""", 200) as FpResult.Success
        assertEquals(emptyList<String>(), r.shadowDeductions)
        assertEquals(null, r.proofStatus)
    }

    @Test
    fun parsesServerFailure() {
        val r = ResponseParser.parseIdentify("""{"ok":false,"visitorId":null,"trustScore":0,"reason":"seal_invalid"}""", 400)
        assertEquals(FpResult.Failure("seal_invalid", 400), r)
    }

    @Test
    fun malformedOrIncompleteBodiesAreFailures() {
        assertEquals(FpResult.Failure("bad_response", 502), ResponseParser.parseIdentify("<html>", 502))
        assertEquals(FpResult.Failure("bad_response", 200), ResponseParser.parseIdentify("""{"ok":true,"visitorId":null}""", 200))
    }

    @Test
    fun parsesNonce() {
        assertEquals("v2.x", ResponseParser.parseNonce("""{"ok":true,"nonce":"v2.x","expiresIn":300}"""))
        assertNull(ResponseParser.parseNonce("""{"ok":false}"""))
        assertNull(ResponseParser.parseNonce("nope"))
    }
}
