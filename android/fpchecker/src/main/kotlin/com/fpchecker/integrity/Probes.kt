package com.fpchecker.integrity

/**
 * Runs independent checks; FIRED if any fires, UNAVAILABLE if none fired but one could not run,
 * else CLEAN. A check that throws never hides evidence found by another check.
 */
private fun anyOf(vararg checks: () -> Boolean): ProbeResult {
    var failed = false
    for (check in checks) {
        try {
            if (check()) return ProbeResult.FIRED
        } catch (e: VirtualMachineError) {
            throw e
        } catch (_: Throwable) {
            // Includes LinkageError from class probing; evidence from the other checks must survive.
            failed = true
        }
    }
    return if (failed) ProbeResult.UNAVAILABLE else ProbeResult.CLEAN
}

private fun tri(value: Boolean?): ProbeResult = when (value) {
    null -> ProbeResult.UNAVAILABLE
    true -> ProbeResult.FIRED
    false -> ProbeResult.CLEAN
}

private const val MAPS_LIMIT = 512 * 1024
private const val MOUNTS_LIMIT = 64 * 1024
private const val FRIDA_PORT = 27042
private const val PORT_TIMEOUT_MS = 100

internal object RootProbe : Probe {
    override val code = "root"
    override fun run(env: ProbeEnv) = anyOf(
        { env.pathDirs().any { env.fileExists("${it.trimEnd('/')}/su") } },
        { env.prop("ro.build.tags")?.contains("test-keys") == true },
        { env.readText("/proc/self/mounts", MOUNTS_LIMIT)?.contains("magisk", ignoreCase = true) == true },
    )
}

internal object HookProbe : Probe {
    override val code = "hook"
    override fun run(env: ProbeEnv) = anyOf(
        { env.readText("/proc/self/maps", MAPS_LIMIT)?.contains("frida-agent") == true },
        { env.classExists("de.robv.android.xposed.XposedBridge") },
        { env.canConnectLocal(FRIDA_PORT, PORT_TIMEOUT_MS) },
    )
}

internal object EmulatorProbe : Probe {
    override val code = "emulator"
    override fun run(env: ProbeEnv) = anyOf(
        { env.prop("ro.kernel.qemu") == "1" },
        { env.prop("ro.hardware").let { it == "ranchu" || it == "goldfish" } },
    )
}

internal object DebuggerProbe : Probe {
    override val code = "debugger"
    override fun run(env: ProbeEnv) = anyOf(
        { env.debuggerConnected() },
        { env.appDebuggable() },
    )
}

internal object DevOptsProbe : Probe {
    override val code = "devopts"
    override fun run(env: ProbeEnv) = anyOf(
        { env.globalSetting("development_settings_enabled") == "1" },
        { env.globalSetting("adb_enabled") == "1" },
    )
}

internal object MitmProbe : Probe {
    override val code = "mitm"
    override fun run(env: ProbeEnv) = anyOf(
        { env.userCaAliases().any { it.startsWith("user:") } },
        { env.httpProxySet() },
    )
}

internal object VpnProbe : Probe {
    override val code = "vpn"
    override fun run(env: ProbeEnv) = tri(env.vpnActive())
}

internal object MockLocationProbe : Probe {
    override val code = "mock_location"
    override fun run(env: ProbeEnv) = tri(env.lastLocationMock())
}

/** Virtual multi-app containers and OEM dual-app users. Work profiles and private space keep the standard path. */
internal object CloneProbe : Probe {
    override val code = "clone"
    private val CLONE_USERS = setOf(95, 96, 97, 98, 99, 999)

    override fun run(env: ProbeEnv): ProbeResult {
        val pkg = env.packageName()
        val dir = env.dataDir().trimEnd('/')
        val standard = dir == "/data/data/$pkg" || Regex("^/data/user/[0-9]+/${Regex.escape(pkg)}$").matches(dir)
        val userId = env.uid() / 100_000
        return if (!standard || userId in CLONE_USERS) ProbeResult.FIRED else ProbeResult.CLEAN
    }
}

internal val ALL_PROBES: List<Probe> = listOf(
    RootProbe, HookProbe, EmulatorProbe, DebuggerProbe, DevOptsProbe, MitmProbe, VpnProbe, MockLocationProbe, CloneProbe,
)
