package com.fpchecker.integrity

import android.content.Context

/** UTC day number (since 1970-01-01) of the system setup, from the first-install time of a system package. */
internal object SetupDay {
    private const val MILLIS_PER_DAY = 86_400_000L
    private const val MAX_DAY = 999_999L
    private val PACKAGES = listOf("com.google.android.gms", "android")

    fun dayOf(firstInstallMillis: Long): Int? {
        if (firstInstallMillis <= 0) return null
        val day = firstInstallMillis / MILLIS_PER_DAY
        return if (day in 0..MAX_DAY) day.toInt() else null
    }

    fun read(ctx: Context): Int? {
        for (pkg in PACKAGES) {
            try {
                val millis = ctx.packageManager.getPackageInfo(pkg, 0).firstInstallTime
                dayOf(millis)?.let { return it }
            } catch (_: Exception) {
                // Package invisible or absent: try the next one.
            }
        }
        return null
    }
}
