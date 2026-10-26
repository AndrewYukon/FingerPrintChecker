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
            var read = 0
            while (read < maxBytes) {
                val n = input.read(buffer, read, maxBytes - read)
                if (n < 0) break
                read += n
            }
            return String(buffer, 0, read, Charsets.ISO_8859_1)
        }
    }

    override fun prop(name: String): String? = when (name) {
        "ro.build.tags" -> Build.TAGS
        "ro.hardware" -> Build.HARDWARE
        else -> getprop(name)
    }

    private fun getprop(name: String): String? {
        val process = ProcessBuilder("/system/bin/getprop", name).redirectErrorStream(true).start()
        try {
            val out = process.inputStream.bufferedReader().use { it.readText().trim() }
            return out.ifEmpty { null }
        } finally {
            process.destroy()
        }
    }

    override fun globalSetting(name: String): String? = Settings.Global.getString(ctx.contentResolver, name)

    override fun canConnectLocal(port: Int, timeoutMs: Int): Boolean {
        Socket().use { socket ->
            return try {
                socket.connect(InetSocketAddress("127.0.0.1", port), timeoutMs)
                true
            } catch (_: ConnectException) {
                false
            }
        }
    }

    override fun classExists(name: String): Boolean = try {
        Class.forName(name, false, ctx.classLoader)
        true
    } catch (_: ClassNotFoundException) {
        false
    }

    override fun debuggerConnected(): Boolean = Debug.isDebuggerConnected() || Debug.waitingForDebugger()

    override fun appDebuggable(): Boolean = (ctx.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

    override fun userCaAliases(): List<String> {
        val store = KeyStore.getInstance("AndroidCAStore")
        store.load(null, null)
        return store.aliases().toList()
    }

    override fun httpProxySet(): Boolean {
        if (!System.getProperty("http.proxyHost").isNullOrBlank()) return true
        val global = Settings.Global.getString(ctx.contentResolver, "http_proxy")
        return !global.isNullOrBlank() && global != ":0"
    }

    override fun vpnActive(): Boolean? {
        if (!granted(Manifest.permission.ACCESS_NETWORK_STATE)) return null
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }

    override fun lastLocationMock(): Boolean? {
        if (!granted(Manifest.permission.ACCESS_FINE_LOCATION) && !granted(Manifest.permission.ACCESS_COARSE_LOCATION)) return null
        val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        // isLocationEnabled exists from API 28; below that the cached fix is read directly.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && !lm.isLocationEnabled) return null
        for (provider in lm.getProviders(true)) {
            val location = lm.getLastKnownLocation(provider) ?: continue
            if (isMock(location)) return true
        }
        return false
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
