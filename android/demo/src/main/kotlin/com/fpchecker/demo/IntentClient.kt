package com.fpchecker.demo

import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** Outcome of asking the demo backend for a protocol v2 intent. */
sealed class IntentResult {
    data class Token(val intentToken: String) : IntentResult()
    data class Failure(val reason: String, val httpStatus: Int) : IntentResult()
}

/** POST {} to [url]; blocking, call off the main thread. */
fun fetchIntent(url: String): IntentResult {
    val connection = try {
        URL(url).openConnection() as HttpURLConnection
    } catch (_: IOException) {
        return IntentResult.Failure("bad_config", 0)
    }
    return try {
        connection.requestMethod = "POST"
        connection.connectTimeout = 10_000
        connection.readTimeout = 10_000
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json")
        connection.outputStream.use { it.write("{}".toByteArray()) }
        val status = connection.responseCode
        val body = (if (status in 200..299) connection.inputStream else connection.errorStream)
            ?.bufferedReader()?.use { it.readText() }.orEmpty()
        val json = runCatching { JSONObject(body) }.getOrNull()
        val token = json?.optString("intentToken").orEmpty()
        if (status == 200 && token.isNotEmpty()) {
            IntentResult.Token(token)
        } else {
            IntentResult.Failure(json?.optString("error")?.ifEmpty { null } ?: "bad_response", status)
        }
    } catch (_: IOException) {
        IntentResult.Failure("network", 0)
    } finally {
        connection.disconnect()
    }
}
