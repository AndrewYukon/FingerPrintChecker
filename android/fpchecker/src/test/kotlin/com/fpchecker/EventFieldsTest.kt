package com.fpchecker

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EventFieldsTest {
    private val comps = listOf(Component("android.id", "1a2b3c4d5e6f7081"))

    private fun invalid(linkedId: String? = null, tags: Map<String, Any?>? = null): String =
        (EventFields.validate(linkedId, tags) as EventFields.Invalid).reason

    private fun ok(linkedId: String? = null, tags: Map<String, Any?>? = null): EventFields.Ok =
        EventFields.validate(linkedId, tags) as EventFields.Ok

    @Test
    fun nothingSetIsOkAndEmpty() {
        val f = ok()
        assertNull(f.linkedId)
        assertNull(f.tags)
    }

    @Test
    fun acceptsBoundaryLinkedIds() {
        assertEquals("a", ok("a").linkedId)
        assertEquals(256, ok("a".repeat(256)).linkedId!!.length)
    }

    @Test
    fun rejectsBadLinkedIds() {
        assertEquals("invalid_linked_id", invalid(linkedId = ""))
        assertEquals("invalid_linked_id", invalid(linkedId = "a".repeat(257)))
        assertEquals("invalid_linked_id", invalid(linkedId = "a\nb"))
        assertEquals("invalid_linked_id", invalid(linkedId = "a\u0000b"))
        assertEquals("invalid_linked_id", invalid(linkedId = "a\u007fb"))
    }

    @Test
    fun tagsDepthFollowsTheServerRule() {
        ok(tags = mapOf("a" to mapOf("b" to mapOf("c" to 1))))
        ok(tags = mapOf("a" to mapOf("b" to 1), "l" to listOf(1, "x", true, null)))
        // an array inside an array is level 3: refused
        assertEquals("invalid_tags", invalid(tags = mapOf("x" to listOf(listOf<Int>()))))
        // object at level 4
        assertEquals("invalid_tags", invalid(tags = mapOf("a" to mapOf("b" to mapOf("c" to mapOf("d" to 1))))))
        // {a:{b:[1]}}: the array is level 3, so it is refused
        assertEquals("invalid_tags", invalid(tags = mapOf("a" to mapOf("b" to listOf(1)))))
    }

    @Test
    fun rejectsUnsupportedValuesAndNonFiniteNumbers() {
        assertEquals("invalid_tags", invalid(tags = mapOf("a" to Any())))
        assertEquals("invalid_tags", invalid(tags = mapOf("a" to Double.NaN)))
        assertEquals("invalid_tags", invalid(tags = mapOf("a" to Float.POSITIVE_INFINITY)))
        @Suppress("UNCHECKED_CAST")
        val badKey = mapOf(1 to "x") as Map<String, Any?>
        assertEquals("invalid_tags", invalid(tags = badKey))
    }

    @Test
    fun tagsSizeIsMeasuredInUtf8Bytes() {
        // {"k":"<n>"}: 8 bytes of framing
        assertTrue(EventFields.validate(null, mapOf("k" to "a".repeat(4096 - 8))) is EventFields.Ok)
        assertEquals("invalid_tags", invalid(tags = mapOf("k" to "a".repeat(4096 - 7))))
        // 3-byte characters: 1366 * 3 = 4098 > 4096 although only 1366 chars
        assertEquals("invalid_tags", invalid(tags = mapOf("k" to "€".repeat(1366))))
        // slashes are not counted as escapes (JSON.stringify does not escape them)
        assertTrue(EventFields.validate(null, mapOf("k" to "/".repeat(4096 - 8))) is EventFields.Ok)
    }

    @Test
    fun bodiesCarryTheFieldsOnlyWhenGiven() {
        val f = ok("order_42", mapOf("page" to "checkout", "n" to listOf(1, 2)))
        for (body in listOf(
            JSONObject(RequestBody.build("n", "s", comps, "android-0.4.0", null, null, f)),
            JSONObject(RequestBody.buildV2("i", "c", comps, "android-0.4.0", null, null, f)),
        )) {
            assertEquals("order_42", body.getString("linkedId"))
            assertEquals("checkout", body.getJSONObject("tags").getString("page"))
            assertEquals(2, body.getJSONObject("tags").getJSONArray("n").length())
        }
        for (body in listOf(
            JSONObject(RequestBody.build("n", "s", comps, "v", null, null)),
            JSONObject(RequestBody.buildV2("i", "c", comps, "v", null, null)),
            JSONObject(RequestBody.buildV2("i", "c", comps, "v", null, null, ok())),
        )) {
            assertFalse(body.has("linkedId"))
            assertFalse(body.has("tags"))
        }
    }

    @Test
    fun parsesEventIdFromV2AndV1() {
        val v2 = """{"ok":true,"protocolVersion":2,"attestation":"fpa1.abc","eventId":"ev_0123456789ABCDEFGHJK"}"""
        assertEquals("ev_0123456789ABCDEFGHJK", (ResponseParser.parseIdentifyV2(v2, 200) as FpIdentifyResult.Success).eventId)
        val v1 = """{"ok":true,"visitorId":"a4_x","isNew":true,"eventId":"ev_0123456789ABCDEFGHJK","attestation":{"token":"fpa1.x"}}"""
        assertEquals("ev_0123456789ABCDEFGHJK", (ResponseParser.parseIdentify(v1, 200) as FpResult.Success).eventId)
    }

    @Test
    fun eventIdIsNullFromOlderServers() {
        val v2 = """{"ok":true,"protocolVersion":2,"attestation":"fpa1.abc"}"""
        assertNull((ResponseParser.parseIdentifyV2(v2, 200) as FpIdentifyResult.Success).eventId)
        val v1 = """{"ok":true,"visitorId":"a4_x","eventId":null}"""
        assertNull((ResponseParser.parseIdentify(v1, 200) as FpResult.Success).eventId)
    }
}
