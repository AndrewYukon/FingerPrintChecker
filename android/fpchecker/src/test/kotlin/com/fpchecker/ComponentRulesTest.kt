package com.fpchecker

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ComponentRulesTest {
    private fun raw(
        androidId: String? = "1a2b3c4d5e6f7081",
        drm: ByteArray? = byteArrayOf(1, 2, 3),
        sim: String? = "DE",
        net: String? = "de",
        tz: String? = "Europe/Berlin",
        fp: String? = "google/x",
        hw: String? = "panther",
        sdk: Int = 34,
        model: String? = "Pixel 7",
    ) = RawSignals(androidId, drm, sim, net, tz, fp, hw, sdk, model)

    @Test
    fun androidIdIsLowercasedAndLeftPadded() {
        assertEquals("00000000000abcde", ComponentRules.normalizeAndroidId("ABCDE"))
        assertEquals("1a2b3c4d5e6f7081", ComponentRules.normalizeAndroidId("1A2B3C4D5E6F7081"))
    }

    @Test
    fun androidIdOmittedWhenUnusable() {
        assertNull(ComponentRules.normalizeAndroidId(null))
        assertNull(ComponentRules.normalizeAndroidId(""))
        assertNull(ComponentRules.normalizeAndroidId("0"))
        assertNull(ComponentRules.normalizeAndroidId("0000000000000000"))
        assertNull(ComponentRules.normalizeAndroidId("9774d56d682e549c"))
        assertNull(ComponentRules.normalizeAndroidId("9774D56D682E549C"))
        assertNull(ComponentRules.normalizeAndroidId("not-hex"))
        assertNull(ComponentRules.normalizeAndroidId("00000000000000001"))
    }

    @Test
    fun mediaDrmIdIsSha256HexAndOmittedWhenDegenerate() {
        val hashed = ComponentRules.hashMediaDrmId(byteArrayOf(1, 2, 3))
        assertEquals(Crypto.sha256Hex("\u0001\u0002\u0003"), hashed)
        assertEquals(64, hashed!!.length)
        assertNull(ComponentRules.hashMediaDrmId(null))
        assertNull(ComponentRules.hashMediaDrmId(ByteArray(0)))
        assertNull(ComponentRules.hashMediaDrmId(ByteArray(32)))
    }

    @Test
    fun countryNormalisation() {
        assertEquals("de", ComponentRules.normalizeCountry("DE"))
        assertEquals("", ComponentRules.normalizeCountry(null))
        assertEquals("", ComponentRules.normalizeCountry(""))
        assertEquals("", ComponentRules.normalizeCountry("deu"))
        assertEquals("", ComponentRules.normalizeCountry("1x"))
    }

    @Test
    fun valuesAreTruncatedToTheirLimits() {
        val long = "x".repeat(400)
        val comps = ComponentRules.build(raw(fp = long, hw = long, model = long, tz = long))
        val byKey = comps.associate { it.key to it.value }
        assertEquals(256, byKey.getValue("android.buildFingerprint").length)
        assertEquals(64, byKey.getValue("android.hardware").length)
        assertEquals(64, byKey.getValue("android.model").length)
        assertEquals(256, byKey.getValue("android.timezone").length)
        assertTrue(ComponentRules.validate(comps).isEmpty())
    }

    @Test
    fun truncationDoesNotSplitSurrogatePairs() {
        val s = "a".repeat(63) + "😀" // 63 + pair = 65 UTF-16 units
        val cut = ComponentRules.truncateSafe(s, 64)
        assertEquals(63, cut.length)
    }

    @Test
    fun absentSignalsAreOmittedNotFaked() {
        val comps = ComponentRules.build(raw(androidId = "9774d56d682e549c", drm = null, tz = null, fp = "", model = null))
        val keys = comps.map { it.key }
        assertTrue("android.id" !in keys)
        assertTrue("android.mediaDrmId" !in keys)
        assertTrue("android.timezone" !in keys)
        assertTrue("android.buildFingerprint" !in keys)
        assertTrue("android.model" !in keys)
        // No identity key left: validator must flag it.
        assertTrue(ComponentRules.validate(comps).contains("no identity key"))
    }

    @Test
    fun countriesAreSentAsEmptyStringWhenAbsent() {
        val comps = ComponentRules.build(raw(sim = null, net = null)).associate { it.key to it.value }
        assertEquals("", comps["android.simCountry"])
        assertEquals("", comps["android.networkCountry"])
    }

    @Test
    fun fullyPopulatedBuildValidates() {
        val comps = ComponentRules.build(raw())
        assertEquals(emptyList<String>(), ComponentRules.validate(comps))
        assertEquals("34", comps.first { it.key == "android.sdkInt" }.value)
    }

    @Test
    fun validatorRejectsBadValues() {
        fun errs(vararg c: Component) = ComponentRules.validate(listOf(Component("android.id", "1a2b3c4d5e6f7081")) + c)
        assertTrue(errs(Component("android.id", "1a2b3c4d5e6f7081")).any { it.startsWith("duplicate") })
        assertTrue(errs(Component("android.mediaDrmId", "abc")).isNotEmpty())
        assertTrue(errs(Component("android.simCountry", "DE")).isNotEmpty())
        assertTrue(errs(Component("android.sdkInt", "34x")).isNotEmpty())
        assertTrue(errs(Component("android.hardware", "h".repeat(65))).isNotEmpty())
        assertTrue(errs(Component("ios.model", "x")).isNotEmpty())
        assertTrue(ComponentRules.validate(listOf(Component("android.id", "9774d56d682e549c"))).isNotEmpty())
    }
}
