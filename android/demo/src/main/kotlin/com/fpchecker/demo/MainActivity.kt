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
    /** Last v2 attestation, for the internal claim test (MatrixClaim.kt); one claim uses it up. */
    private var attestation: String? = null

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
                val token = attestation ?: return@setOnClickListener
                val round = roundInput.text.toString().trim()
                if (!isRound(round)) return@setOnClickListener
                attestation = null
                claimButton.isEnabled = false
                matrixClaim(config, intentUrl, token, round) { line -> output.text = getString(R.string.two_blocks, line, output.text) }
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
                            attestation = (result as? FpIdentifyResult.Success)?.attestation
                            claimButton.isEnabled = attestation != null
                            output.text = renderV2(result)
                        }
                    }
                }.start()
            }
        }
    }

    /**
     * Internal test: one real claim of [round]. A first claim asks for proof of work: identify again
     * with that many bits (a second checker, closed afterwards) and claim once more. [show] runs on the main thread.
     */
    private fun matrixClaim(config: FpCheckerConfig, intentUrl: String, token: String, round: String, show: (String) -> Unit) {
        val claimUrl = claimUrlFor(intentUrl)
        val describe = { answer: ClaimAnswer ->
            when (answer) {
                is ClaimAnswer.Decision -> getString(R.string.claim_line, round, answer.action.uppercase(), answer.reason)
                is ClaimAnswer.Failure -> getString(R.string.claim_error, round, answer.reason, answer.httpStatus)
            }
        }
        Thread {
            val first = postClaim(claimUrl, token, round)
            val bits = (first as? ClaimAnswer.Decision)?.takeIf { it.action == "pow" }?.powDifficulty
            if (bits == null) {
                runOnUiThread { show(describe(first)) }
                return@Thread
            }
            val intent = fetchIntent(intentUrl)
            if (intent !is IntentResult.Token) {
                runOnUiThread { show(describe(ClaimAnswer.Failure("pow_intent_failed", 0))) }
                return@Thread
            }
            val proving = FpChecker(this, config.copy(powDifficulty = bits))
            proving.identify(intent.intentToken) { result ->
                proving.close()
                val proven = (result as? FpIdentifyResult.Success)?.attestation
                if (proven == null) {
                    show(describe(ClaimAnswer.Failure("pow_identify_failed", 0)))
                } else {
                    Thread { postClaim(claimUrl, proven, round).let { runOnUiThread { show(describe(it)) } } }.start()
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
