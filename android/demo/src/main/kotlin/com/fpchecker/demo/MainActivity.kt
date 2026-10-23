package com.fpchecker.demo

import android.app.Activity
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import com.fpchecker.FpChecker
import com.fpchecker.FpCheckerConfig
import com.fpchecker.FpIdentifyResult
import com.fpchecker.FpResult

class MainActivity : Activity() {
    private var checker: FpChecker? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val output = findViewById<TextView>(R.id.output)
        val button = findViewById<Button>(R.id.identifyButton)
        val buttonV2 = findViewById<Button>(R.id.identifyV2Button)

        val config = try {
            FpCheckerConfig(
                baseUrl = BuildConfig.FP_BASE_URL.ifEmpty { FpCheckerConfig.DEFAULT_BASE_URL },
                publishableKey = BuildConfig.FP_PK,
                sealKey = BuildConfig.FP_SEAL_KEY,
                cloudProjectNumber = BuildConfig.FP_CLOUD_PROJECT.toLongOrNull(),
            )
        } catch (e: IllegalArgumentException) {
            button.isEnabled = false
            output.text = getString(R.string.config_error, getString(R.string.idle), e.message)
            return
        }
        val fp = FpChecker(this, config)
        checker = fp

        button.setOnClickListener {
            button.isEnabled = false
            output.setText(R.string.working)
            fp.identify { result ->
                button.isEnabled = true
                output.text = render(result)
            }
        }

        val claimButton = findViewById<Button>(R.id.claimButton)
        val roundInput = findViewById<EditText>(R.id.roundInput)
        val intentUrl = BuildConfig.FP_INTENT_URL
        if (intentUrl.isNotEmpty()) {
            findViewById<View>(R.id.claimRow).visibility = View.VISIBLE
            claimButton.setOnClickListener {
                val round = roundInput.text.toString().trim()
                if (!isRound(round)) return@setOnClickListener
                claimButton.isEnabled = false
                matrixClaim(config, intentUrl, round) { line ->
                    claimButton.isEnabled = true
                    output.text = getString(R.string.two_blocks, line, output.text)
                }
            }
            buttonV2.visibility = View.VISIBLE
            buttonV2.setOnClickListener {
                buttonV2.isEnabled = false
                output.setText(R.string.working)
                Thread {
                    when (val intent = fetchIntent(intentUrl)) {
                        is IntentResult.Failure -> runOnUiThread {
                            buttonV2.isEnabled = true
                            output.text = getString(R.string.intent_failed, intent.reason, intent.httpStatus)
                        }
                        is IntentResult.Token -> fp.identify(intent.intentToken) { result ->
                            buttonV2.isEnabled = true
                            output.text = renderV2(result)
                        }
                    }
                }.start()
            }
        }
    }

    /**
     * Internal test: one real claim of [round]. Identifies with an intent minted for that round,
     * claims, and when the claim asks for proof of work identifies again with that many bits and
     * claims once more. [show] runs on the main thread.
     */
    private fun matrixClaim(config: FpCheckerConfig, intentUrl: String, round: String, show: (String) -> Unit) {
        val claimUrl = claimUrlFor(intentUrl)
        val describe = { answer: ClaimAnswer ->
            when (answer) {
                is ClaimAnswer.Decision -> getString(R.string.claim_line, round, answer.action.uppercase(), answer.reason)
                is ClaimAnswer.Failure -> getString(R.string.claim_error, round, answer.reason, answer.httpStatus)
            }
        }
        val claim = { attestation: String, next: (ClaimAnswer) -> Unit ->
            Thread { postClaim(claimUrl, attestation, round).let { runOnUiThread { next(it) } } }.start()
        }
        roundAttestation(config, intentUrl, round, null) { first ->
            when (first) {
                is RoundAttestation.Failure -> show(describe(first.answer))
                is RoundAttestation.Token -> claim(first.attestation) { answer ->
                    val bits = (answer as? ClaimAnswer.Decision)?.takeIf { it.action == "pow" }?.powDifficulty
                    if (bits == null) {
                        show(describe(answer))
                    } else {
                        roundAttestation(config, intentUrl, round, bits) { proven ->
                            when (proven) {
                                is RoundAttestation.Failure -> show(describe(proven.answer))
                                is RoundAttestation.Token -> claim(proven.attestation) { show(describe(it)) }
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Identify v2 (a checker of its own, closed afterwards) with an intent minted for [round]'s claim.
     * [done] runs on the main thread.
     */
    private fun roundAttestation(config: FpCheckerConfig, intentUrl: String, round: String, powBits: Int?, done: (RoundAttestation) -> Unit) {
        Thread {
            when (val intent = fetchIntent(intentUrl, round)) {
                is IntentResult.Failure -> runOnUiThread { done(RoundAttestation.Failure(ClaimAnswer.Failure("intent_${intent.reason}", intent.httpStatus))) }
                is IntentResult.Token -> {
                    val proving = FpChecker(this, if (powBits == null) config else config.copy(powDifficulty = powBits))
                    proving.identify(intent.intentToken) { result ->
                        proving.close()
                        done(
                            when (result) {
                                is FpIdentifyResult.Success -> RoundAttestation.Token(result.attestation)
                                is FpIdentifyResult.Failure -> RoundAttestation.Failure(ClaimAnswer.Failure("identify_${result.reason}", result.httpStatus))
                            },
                        )
                    }
                }
            }
        }.start()
    }

    override fun onDestroy() {
        checker?.close()
        super.onDestroy()
    }

    private fun render(result: FpResult): String = when (result) {
        is FpResult.Success -> buildString {
            appendLine("visitorId: ${result.visitorId}")
            appendLine("trustScore: ${result.trustScore ?: "hidden (scoreDetails)"}")
            appendLine("identityConfidence: ${result.identityConfidence ?: "hidden (scoreDetails)"}")
            appendLine("isNew: ${result.isNew}")
            appendLine("deductions: ${result.trustDeductions.joinToString().ifEmpty { "(none)" }}")
            appendLine()
            append(result.rawJson)
        }
        is FpResult.Failure -> "FAILED: ${result.reason} (http ${result.httpStatus})"
    }

    private fun renderV2(result: FpIdentifyResult): String = when (result) {
        is FpIdentifyResult.Success -> buildString {
            appendLine("V2 attestation: ${result.attestation.take(24)}…")
            appendLine("visitorId: ${result.visitorId ?: "hidden (scoreDetails)"}")
            appendLine("trustScore: ${result.trustScore ?: "hidden (scoreDetails)"}")
            appendLine("identityConfidence: ${result.identityConfidence ?: "hidden (scoreDetails)"}")
            appendLine("isNew: ${result.isNew ?: "-"}")
            appendLine("proofStatus: ${result.proofStatus ?: "-"}")
            appendLine("deductions: ${result.trustDeductions.joinToString().ifEmpty { "(none)" }}")
            appendLine()
            append(result.rawJson)
        }
        is FpIdentifyResult.Failure -> "V2 FAILED: ${result.reason} (http ${result.httpStatus})"
    }
}
