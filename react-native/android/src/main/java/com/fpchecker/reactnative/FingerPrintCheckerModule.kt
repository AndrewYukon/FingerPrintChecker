package com.fpchecker.reactnative

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableMap
import com.fpchecker.FpChecker
import com.fpchecker.FpEventOptions
import com.fpchecker.FpIdentifyResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class FingerPrintCheckerModule(private val reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private val handler = IdentifyHandler { config ->
        val checker = FpChecker(reactContext.applicationContext, config)
        object : Identifier {
            override suspend fun identify(intentToken: String, options: FpEventOptions): FpIdentifyResult =
                checker.identify(intentToken, options)

            override fun close() = checker.close()
        }
    }

    override fun getName(): String = NAME

    /** Always resolves exactly once with `{ok: ...}`; never rejects. */
    @ReactMethod
    fun identify(args: ReadableMap, promise: Promise) {
        val once = OnceResolver(Arguments::makeNativeMap, promise::resolve)
        val bridgeError = failureReply("bridge_error", 0)
        val request = try {
            args.toHashMap()
        } catch (_: Throwable) {
            once.resolve(bridgeError)
            return
        }
        if (!scope.isActive) {
            once.resolve(bridgeError)
            return
        }
        val job = scope.launch {
            once.resolve(
                try {
                    handler.handle(request)
                } catch (e: CancellationException) {
                    once.resolve(bridgeError)
                    throw e
                } catch (_: Throwable) {
                    bridgeError
                },
            )
        }
        // Covers a launch cancelled before its body ever ran.
        job.invokeOnCompletion { if (it != null) once.resolve(bridgeError) }
    }

    override fun invalidate() {
        scope.cancel()
        handler.close()
        super.invalidate()
    }

    companion object {
        const val NAME = "FingerPrintCheckerModule"
    }
}
