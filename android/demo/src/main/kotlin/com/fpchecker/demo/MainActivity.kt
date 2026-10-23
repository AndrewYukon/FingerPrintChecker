package com.fpchecker.demo

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import com.fpchecker.FpChecker
import com.fpchecker.FpCheckerConfig
import com.fpchecker.FpResult

class MainActivity : Activity() {
    private var checker: FpChecker? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val output = findViewById<TextView>(R.id.output)
        val button = findViewById<Button>(R.id.identifyButton)

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
}
