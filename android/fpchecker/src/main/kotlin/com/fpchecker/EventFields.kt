package com.fpchecker

import org.json.JSONArray
import org.json.JSONObject

/**
 * The optional customer-supplied event fields (`linkedId`, `tags`). Mirrors the server's rules so a bad value
 * fails before any network call. They are sent beside the signed fields and are never part of the canonical bytes.
 */
internal sealed class EventFields {
    /** Valid (or absent) fields; [linkedId] / [tags] are null when not set. */
    class Ok(val linkedId: String?, val tags: JSONObject?) : EventFields()

    /** [reason] is the server's reason code: `invalid_linked_id` or `invalid_tags`. */
    class Invalid(val reason: String) : EventFields()

    companion object {
        const val LINKED_ID_MAX = 256
        const val TAGS_MAX_BYTES = 4096
        const val TAGS_MAX_DEPTH = 3

        /** null (or no value) means "not set": nothing is sent. */
        fun validate(linkedId: String?, tags: Map<String, Any?>?): EventFields {
            if (linkedId != null && !validLinkedId(linkedId)) return Invalid("invalid_linked_id")
            var tagsJson: JSONObject? = null
            if (tags != null) {
                tagsJson = try {
                    toJsonObject(tags, 1)
                } catch (_: IllegalArgumentException) {
                    return Invalid("invalid_tags")
                }
                // org.json escapes '/', which JSON.stringify (the server's measure) does not.
                val bytes = tagsJson.toString().replace("\\/", "/").toByteArray(Charsets.UTF_8).size
                if (bytes > TAGS_MAX_BYTES) return Invalid("invalid_tags")
            }
            return Ok(linkedId, tagsJson)
        }

        private fun validLinkedId(s: String): Boolean =
            s.length in 1..LINKED_ID_MAX && s.none { it.code <= 0x1f || it.code == 0x7f }

        /** An object at level [depth] is allowed up to level 3; an array only up to level 2 (its elements are one deeper). */
        private fun toJsonObject(map: Map<*, *>, depth: Int): JSONObject {
            require(depth <= TAGS_MAX_DEPTH)
            val out = JSONObject()
            for ((k, v) in map) {
                require(k is String)
                out.put(k, toJson(v, depth + 1))
            }
            return out
        }

        private fun toJson(v: Any?, depth: Int): Any = when (v) {
            null -> JSONObject.NULL
            is String, is Boolean -> v
            is Double -> { require(v.isFinite()); v }
            is Float -> { require(v.isFinite()); v.toDouble() }
            is Number -> v
            is Map<*, *> -> toJsonObject(v, depth)
            is Iterable<*> -> toJsonArray(v.toList(), depth)
            is Array<*> -> toJsonArray(v.toList(), depth)
            else -> throw IllegalArgumentException("unsupported tag value")
        }

        private fun toJsonArray(items: List<Any?>, depth: Int): JSONArray {
            require(depth < TAGS_MAX_DEPTH)
            val out = JSONArray()
            for (item in items) out.put(toJson(item, depth + 1))
            return out
        }
    }
}
