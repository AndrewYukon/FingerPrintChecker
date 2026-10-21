package com.fpchecker

import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** Minimal HTTP transport over HttpURLConnection. No android.* imports. */
internal class ApiClient(
    private val baseUrl: String,
    private val publishableKey: String,
    private val connectTimeoutMs: Int = 10_000,
    private val readTimeoutMs: Int = 15_000,
) {
    internal class Response(val status: Int, val body: String)

    private val root = baseUrl.trimEnd('/')

    /** GET /v1/challenge; throws [IOException] on transport errors. */
    fun challenge(powDifficulty: Int?): Response {
        val query = if (powDifficulty != null) "?difficulty=$powDifficulty" else ""
        return request("GET", "$root/v1/challenge$query", null)
    }

    /** POST /v1/identify; throws [IOException] on transport errors. */
    fun identify(body: String): Response = request("POST", "$root/v1/identify", body)

    private fun request(method: String, url: String, body: String?): Response {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = method
            conn.connectTimeout = connectTimeoutMs
            conn.readTimeout = readTimeoutMs
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("X-Publishable-Key", publishableKey)
            conn.setRequestProperty("Accept", "application/json")
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val status = conn.responseCode
            val stream = if (status in 200..299) conn.inputStream else conn.errorStream
            return Response(status, stream?.let { readBounded(it) }.orEmpty())
        } finally {
            conn.disconnect()
        }
    }

    private fun readBounded(stream: java.io.InputStream): String =
        stream.use { s ->
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(4096)
            while (true) {
                val n = s.read(buf)
                if (n < 0) break
                out.write(buf, 0, n)
                if (out.size() > MAX_RESPONSE_BYTES) throw IOException("response too large")
            }
            out.toString("UTF-8")
        }

    private companion object {
        const val MAX_RESPONSE_BYTES = 256 * 1024
    }
}

internal object RequestBody {
    /** Builds the identify JSON. [pow] is sent as a JSON string, never a number. */
    fun build(
        nonce: String,
        sig: String,
        components: List<Component>,
        agentVersion: String,
        pow: String?,
        integrityToken: String?,
    ): String {
        val comps = JSONArray()
        for (c in components) comps.put(JSONObject().put("key", c.key).put("value", c.value))
        val json = JSONObject()
            .put("platform", "android")
            .put("nonce", nonce)
            .put("sig", sig)
            .put("components", comps)
            .put("agentVersion", agentVersion)
        if (pow != null) json.put("pow", pow)
        if (integrityToken != null) {
            json.put("proof", JSONObject().put("type", "play_integrity").put("token", integrityToken))
        }
        return json.toString()
    }
}
