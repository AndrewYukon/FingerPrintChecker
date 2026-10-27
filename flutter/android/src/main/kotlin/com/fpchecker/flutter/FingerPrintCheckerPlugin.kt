package com.fpchecker.flutter

import android.content.Context
import android.os.Handler
import android.os.Looper
import com.fpchecker.FpChecker
import com.fpchecker.FpEventOptions
import com.fpchecker.FpIdentifyResult
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class FingerPrintCheckerPlugin : FlutterPlugin, MethodChannel.MethodCallHandler {
    private var channel: MethodChannel? = null
    private var handler: IdentifyHandler? = null
    private var scope: CoroutineScope? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        val context: Context = binding.applicationContext
        scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
        handler = IdentifyHandler { config ->
            val checker = FpChecker(context, config)
            object : Identifier {
                override suspend fun identify(intentToken: String, options: FpEventOptions): FpIdentifyResult =
                    checker.identify(intentToken, options)

                override fun close() = checker.close()
            }
        }
        channel = MethodChannel(binding.binaryMessenger, CHANNEL).also { it.setMethodCallHandler(this) }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel?.setMethodCallHandler(null)
        channel = null
        // Cancelling completes every in-flight launch; each one resolves its Result with bridge_error.
        scope?.cancel()
        scope = null
        handler?.close()
        handler = null
    }

    /** Always replies exactly once with `{ok: ...}`, on the main thread; never calls `error`. */
    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        if (call.method != "identify") {
            result.notImplemented()
            return
        }
        val once = OnceResolver<Map<String, Any?>>({ it }) { reply -> onMain { result.success(reply) } }
        val bridgeError = failureReply("bridge_error", 0)
        val activeScope = scope
        val activeHandler = handler
        val request = try {
            (call.arguments as? Map<*, *>)?.entries?.associate { it.key.toString() to it.value }
        } catch (_: Throwable) {
            null
        }
        if (activeScope == null || activeHandler == null || !activeScope.isActive || request == null) {
            once.resolve(bridgeError)
            return
        }
        val job = try {
            activeScope.launch {
                once.resolve(
                    try {
                        activeHandler.handle(request)
                    } catch (e: CancellationException) {
                        once.resolve(bridgeError)
                        throw e
                    } catch (_: Throwable) {
                        bridgeError
                    },
                )
            }
        } catch (_: Throwable) {
            once.resolve(bridgeError)
            return
        }
        // Covers a launch cancelled before its body ever ran.
        job.invokeOnCompletion { if (it != null) once.resolve(bridgeError) }
    }

    private fun onMain(block: () -> Unit) {
        if (Looper.myLooper() == Looper.getMainLooper()) block() else mainHandler.post(block)
    }

    companion object {
        const val CHANNEL = "com.fpchecker/flutter"
    }
}
