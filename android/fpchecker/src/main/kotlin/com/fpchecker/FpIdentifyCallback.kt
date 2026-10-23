package com.fpchecker

/** Java-friendly callback for [FpChecker.identify] with an intent token. Invoked on the main thread. */
public fun interface FpIdentifyCallback {
    public fun onResult(result: FpIdentifyResult)
}
