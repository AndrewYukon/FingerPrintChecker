package com.fpchecker.demo

import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** Internal device/network test: the demo backend's answer to one real claim of round `r<N>`. */
sealed class ClaimAnswer {
    data class Decision(val action: String, val reason: String, val powDifficulty: Int?) : ClaimAnswer()
    data class Failure(val reason: String, val httpStatus: Int) : ClaimAnswer()
}

/** An identify for one round's claim: the attestation to claim with, or why there is none. */
sealed class RoundAttestation {
    data class Token(val attestation: String) : RoundAttestation()
    data class Failure(val answer: ClaimAnswer.Failure) : RoundAttestation()
}

private val ROUND = Regex("^r[0-9]{1,3}$")

fun isRound(round: String): Boolean = ROUND.matches(round)

/** The claim endpoint next to the intent endpoint (`.../intent` -> `.../claim`). */
fun claimUrlFor(intentUrl: String): String = intentUrl.substringBeforeLast('/') + "/claim"

/** POST {attestation, round} to [url]; blocking, call off the main thread. */
fun postClaim(url: String, attestation: String, round: String): ClaimAnswer {
    val connection = try {
        URL(url).openConnection() as HttpURLConnection
    } catch (_: IOException) {
        return ClaimAnswer.Failure("bad_config", 0)
    }
    return try {
        connection.requestMethod = "POST"
        connection.connectTimeout = 15_000
        connection.readTimeout = 15_000
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json")
        val body = JSONObject().put("attestation", attestation).put("round", round).toString()
        connection.outputStream.use { it.write(body.toByteArray()) }
        val status = connection.responseCode
        val text = (if (status in 200..299) connection.inputStream else connection.errorStream)
            ?.bufferedReader()?.use { it.readText() }.orEmpty()
        val json = runCatching { JSONObject(text) }.getOrNull()
        val action = json?.optString("action").orEmpty()
        val reason = json?.optString("reason").orEmpty()
        if (action.isNotEmpty() && reason.isNotEmpty()) {
            val pow = json?.optInt("powDifficulty", 0) ?: 0
            ClaimAnswer.Decision(action, reason, pow.takeIf { it > 0 })
        } else {
            ClaimAnswer.Failure(json?.optString("error")?.ifEmpty { null } ?: "bad_response", status)
        }
    } catch (_: IOException) {
        ClaimAnswer.Failure("network", 0)
    } finally {
        connection.disconnect()
    }
}
