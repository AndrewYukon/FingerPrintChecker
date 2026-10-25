package com.fpchecker

import org.junit.Test
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull

class SealedResultTest {
    private val v2 = """{"ok":true,"protocolVersion":2,"attestation":"fpa1.abc","sealedResult":"fpsr1.payload.tag"}"""
    private val v1 = """{"ok":true,"visitorId":"a4_x","isNew":true,"sealedResult":"fpsr1.payload.tag","attestation":{"token":"fpa1.x"}}"""

    @Test
    fun `answer with sealedResult exposes it`() {
        assertEquals("fpsr1.payload.tag", (ResponseParser.parseIdentifyV2(v2, 200) as FpIdentifyResult.Success).sealedResult)
        assertEquals("fpsr1.payload.tag", (ResponseParser.parseIdentify(v1, 200) as FpResult.Success).sealedResult)
    }

    @Test
    fun `answer without it is null`() {
        val noV2 = """{"ok":true,"protocolVersion":2,"attestation":"fpa1.abc"}"""
        val noV1 = """{"ok":true,"visitorId":"a4_x","isNew":true}"""
        assertNull((ResponseParser.parseIdentifyV2(noV2, 200) as FpIdentifyResult.Success).sealedResult)
        assertNull((ResponseParser.parseIdentify(noV1, 200) as FpResult.Success).sealedResult)
    }

    @Test
    fun `non string or empty sealedResult is null`() {
        for (bad in listOf("null", "5", "{}", "\"\"")) {
            val b2 = """{"ok":true,"protocolVersion":2,"attestation":"fpa1.abc","sealedResult":$bad}"""
            val b1 = """{"ok":true,"visitorId":"a4_x","sealedResult":$bad}"""
            assertNull(bad, (ResponseParser.parseIdentifyV2(b2, 200) as FpIdentifyResult.Success).sealedResult)
            assertNull(bad, (ResponseParser.parseIdentify(b1, 200) as FpResult.Success).sealedResult)
        }
    }
}
