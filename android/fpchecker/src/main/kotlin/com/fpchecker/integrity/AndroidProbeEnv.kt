package com.fpchecker.integrity

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Debug
import android.os.Process
import android.provider.Settings
import java.io.File
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore

/**
 * Real device reads. Methods throw on failure; the probe layer maps that to UNAVAILABLE.
 * Permission-gated reads return null when the host app has not been granted the permission at runtime.
 * Adds no manifest permission of its own.
 */
internal class AndroidProbeEnv(context: Context) : ProbeEnv {
    private val ctx = context.applicationContext

    override fun fileExists(path: String): Boolean = File(path).exists()

    override fun readText(path: String, maxBytes: Int): String? {
        val file = File(path)
        if (!file.exists()) return null
        file.inputStream().use { input ->
            val buffer = ByteArray(maxBytes)
            val fixes = mutableListOf<Boolean?>()
        for (provider in lm.getProviders(true)) {
            // A coarse-only grant makes "gps" throw; the other providers must still be read.
            val location = try {
                lm.getLastKnownLocation(provider)
            } catch (_: SecurityException) {
                continue
            }
            fixes.add(location?.let { isMock(it) })
        }
        return mockLocationVerdict(fixes)
    }

    @Suppress("DEPRECATION") // isFromMockProvider is the only option below API 31
    private fun isMock(location: Location): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) location.isMock else location.isFromMockProvider

    override fun dataDir(): String = ctx.applicationInfo.dataDir

    override fun packageName(): String = ctx.packageName

    override fun uid(): Int = Process.myUid()

    override fun pathDirs(): List<String> = System.getenv("PATH").orEmpty().split(':').filter { it.isNotEmpty() }

    private fun granted(permission: String): Boolean =
        ctx.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
}
