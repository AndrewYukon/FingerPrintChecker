package com.fpchecker

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ProtocolVectorsTest {
    private val vectors: JSONObject = run {
        val path = System.getProperty("fpchecker.vectors")
        assertNotNull("fpchecker.vectors system property must be set", path)
        JSONObject(File(path!!).readText(Charsets.UTF_8))
    }
    private val sealKey = vectors.getString("sealKey")
    private val nonce = vectors.getString("nonce")

    private fun androidCases() =
        (0 until vectors.getJSONArray("cases").length())
            .map { vectors.getJSONArray("cases").getJSONObject(it) }

    private fun componentsOf(case: JSONObject): List<Component> {
        val arr = case.getJSONArray("components")
        return List(arr.length()) { Component(arr.getJSONObject(it).getString("key"), arr.getJSONObject(it).getString("value")) }
    }

    @Test
    fun everyCaseMatchesCanonicalSigAndRequestHash() {
        val cases = androidCases()
        assertTrue("expected the 4 shipped vectors", cases.size >= 4)
        for (case in cases) {
            val name = case.getString("name")
            val components = componentsOf(case)
            val canonical = Canonical.payload(nonce, components)
            assertEquals("$name canonical", case.getString("canonical"), canonical)
            assertEquals("$name sig", case.getString("sig"), Canonical.seal(sealKey, canonical))
            assertEquals("$name requestHash", case.getString("requestHashHex"), Canonical.requestHash(canonical))
        }
    }

    @Test
    fun canonicalIsIndependentOfInputOrder() {
        val case = androidCases().first { it.getString("name") == "android-full" }
        val components = componentsOf(case)
        assertEquals(
            Canonical.payload(nonce, components),
            Canonical.payload(nonce, components.reversed()),
        )
    }

    @Test
    fun androidVectorPassesTheSdkValidator() {
        val case = androidCases().first { it.getString("platform") == "android" }
        assertEquals(emptyList<String>(), ComponentRules.validate(componentsOf(case)))
    }

    @Test
    fun powSolutionMatchesVector() {
        val pow = vectors.getJSONObject("pow")
        val bits = pow.getInt("bits")
        val solution = Pow.solve(pow.getString("nonce"), bits)
        assertEquals(pow.getString("solution"), solution)
    }

    @Test
    fun powSolveCanBeCancelled() {
        assertEquals(null, Pow.solve("n", 28) { false })
    }

    @Test
    fun leadingZeroBitsCountsAcrossBytes() {
        assertEquals(0, Pow.leadingZeroBits(byteArrayOf(0x80.toByte())))
        assertEquals(7, Pow.leadingZeroBits(byteArrayOf(0x01)))
        assertEquals(12, Pow.leadingZeroBits(byteArrayOf(0x00, 0x0f)))
        assertEquals(16, Pow.leadingZeroBits(byteArrayOf(0x00, 0x00)))
    }
}
