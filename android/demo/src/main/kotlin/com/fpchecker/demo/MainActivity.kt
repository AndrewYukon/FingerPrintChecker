package com.fpchecker.demo

import android.app.Activity
import android.os.Bundle
import android.view.View
import android.widget.Button
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

        val intentUrl = BuildConfig.FP_INTENT_URL
        if (intentUrl.isNotEmpty()) {
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
