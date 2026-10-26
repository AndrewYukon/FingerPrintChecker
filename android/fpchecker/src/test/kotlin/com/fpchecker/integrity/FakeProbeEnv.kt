package com.fpchecker.integrity

internal open class FakeProbeEnv(
    private val files: Set<String> = emptySet(),
    private val texts: Map<String, String> = emptyMap(),
    private val props: Map<String, String> = emptyMap(),
    private val settings: Map<String, String> = emptyMap(),
    private val frida: Boolean = false,
    private val classes: Set<String> = emptySet(),
    private val debugger: Boolean = false,
    private val debuggable: Boolean = false,
    private val aliases: List<String> = emptyList(),
    private val proxy: Boolean = false,
    private val vpn: Boolean? = false,
    private val mock: Boolean? = false,
    private val data: String = "/data/user/0/com.x",
    private val pkg: String = "com.x",
    private val uidValue: Int = 10123,
    private val path: List<String> = listOf("/system/bin", "/system/xbin"),
) : ProbeEnv {
    override fun fileExists(path: String) = path in files
    override fun readText(path: String, maxBytes: Int) = texts[path]
    override fun fileContainsAny(path: String, markers: List<String>) = texts[path]?.let { text -> markers.any { text.contains(it) } } ?: false
    override fun prop(name: String) = props[name]
    override fun globalSetting(name: String) = settings[name]
    override fun canConnectLocal(port: Int, timeoutMs: Int) = frida && port == 27042
    override fun classExists(name: String) = name in classes
    override fun debuggerConnected() = debugger
    override fun appDebuggable() = debuggable
    override fun userCaAliases() = aliases
    override fun httpProxySet() = proxy
    override fun vpnActive() = vpn
    override fun lastLocationMock() = mock
    override fun dataDir() = data
    override fun packageName() = pkg
    override fun uid() = uidValue
    override fun pathDirs() = path
}

/** Every read throws, as a SecurityException from a locked-down device would. */
internal class ThrowingProbeEnv : ProbeEnv {
    private fun boom(): Nothing = throw SecurityException("denied")
    override fun fileExists(path: String): Boolean = boom()
    override fun readText(path: String, maxBytes: Int): String? = boom()
    override fun fileContainsAny(path: String, markers: List<String>): Boolean = boom()
    override fun prop(name: String): String? = boom()
    override fun globalSetting(name: String): String? = boom()
    override fun canConnectLocal(port: Int, timeoutMs: Int): Boolean = boom()
    override fun classExists(name: String): Boolean = boom()
    override fun debuggerConnected(): Boolean = boom()
    override fun appDebuggable(): Boolean = boom()
    override fun userCaAliases(): List<String> = boom()
    override fun httpProxySet(): Boolean = boom()
    override fun vpnActive(): Boolean? = boom()
    override fun lastLocationMock(): Boolean? = boom()
    override fun dataDir(): String = boom()
    override fun packageName(): String = boom()
    override fun uid(): Int = boom()
    override fun pathDirs(): List<String> = boom()
}
