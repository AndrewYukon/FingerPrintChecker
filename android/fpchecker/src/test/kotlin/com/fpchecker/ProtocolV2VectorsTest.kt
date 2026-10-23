package com.fpchecker

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.util.Base64

class ProtocolV2VectorsTest {
    private val vectors: JSONObject = run {
        val path = System.getProperty("fpchecker.vectors.v2")
        assertNotNull("fpchecker.vectors.v2 system property must be set", path)
        JSONObject(File(path!!).readText(Charsets.UTF_8))
    }

    private fun inputs(input: JSONObject): Array<Any> {
        val arr = input.getJSONArray("components")
        val comps = List(arr.length()) {
            val c = arr.getJSONObject(it)
            JcsComponent(c.getString("key"), c.getString("value"), if (c.has("hash")) c.getString("hash") else null)
        }
        return arrayOf(input.getString("platform"), input.getString("agentVersion"), input.getString("challenge"), comps)
    }

    @Suppress("UNCHECKED_CAST")
    private fun canonicalOf(input: JSONObject): String {
        val a = inputs(input)
        return Jcs.identify(a[0] as String, a[1] as String, a[2] as String, a[3] as List<JcsComponent>)
    }

    @Test
    fun domainMatches() {
        assertEquals(vectors.getString("domain"), Jcs.DOMAIN)
    }

    @Test
    fun everyAcceptCaseMatches() {
        val accept = vectors.getJSONArray("accept")
        assertTrue("expected the shipped accept vectors", accept.length() >= 8)
        for (i in 0 until accept.length()) {
            val case = accept.getJSONObject(i)
            val name = case.getString("name")
            val canonical = canonicalOf(case.getJSONObject("input"))
            assertEquals("$name canonical", case.getString("canonical"), canonical)
            val bytes = canonical.toByteArray(Charsets.UTF_8)
            assertEquals("$name binding", case.getString("requestBindingHex"), Jcs.requestHashHex(bytes))
            assertEquals(
                "$name clientDataHash",
                case.getString("clientDataHashBase64"),
                Base64.getEncoder().encodeToString(Crypto.sha256(bytes)),
            )
        }
    }

    @Test
    fun everyRejectCaseIsRefused() {
        val reject = vectors.getJSONArray("reject")
        assertTrue("expected the shipped reject vectors", reject.length() >= 7)
        for (i in 0 until reject.length()) {
            val case = reject.getJSONObject(i)
            try {
                canonicalOf(case.getJSONObject("input"))
                fail("${case.getString("name")} must be refused")
            } catch (_: IllegalArgumentException) {
                // expected
            }
        }
    }
}
