package com.fpchecker.integrity

/**
 * Everything a probe may read from the device. Pure interface so probes are unit-tested on the JVM.
 * Methods may throw; a `Boolean?` that is null means "no permission to know" and maps to UNAVAILABLE.
 */
internal interface ProbeEnv {
    fun fileExists(path: String): Boolean

    /** Up to [maxBytes] of the file as text, or null when it does not exist. */
    fun readText(path: String, maxBytes: Int): String?

    /** True when any line of the file contains one of [markers]; streamed, no size cap. False when the file is absent. */
    fun fileContainsAny(path: String, markers: List<String>): Boolean
    fun prop(name: String): String?
    fun globalSetting(name: String): String?

    /** True when something accepts a TCP connection on 127.0.0.1:[port]; false when refused. */
    fun canConnectLocal(port: Int, timeoutMs: Int): Boolean
    fun classExists(name: String): Boolean
    fun debuggerConnected(): Boolean
    fun appDebuggable(): Boolean
    fun userCaAliases(): List<String>
    fun httpProxySet(): Boolean
    fun vpnActive(): Boolean?
    fun lastLocationMock(): Boolean?
    fun dataDir(): String
    fun packageName(): String
    fun uid(): Int
    fun pathDirs(): List<String>
}
