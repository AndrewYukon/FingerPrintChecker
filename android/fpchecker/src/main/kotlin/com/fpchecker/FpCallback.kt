package com.fpchecker

/** Java-friendly callback for [FpChecker.identify]. Invoked on the main thread. */
public fun interface FpCallback {
    public fun onResult(result: FpResult)
}
