package com.fpchecker.integrity

import org.junit.Assert.assertEquals
import org.junit.Test

class ProbesTest {
    private val fired = ProbeResult.FIRED
    private val clean = ProbeResult.CLEAN
    private val unavailable = ProbeResult.UNAVAILABLE

    @Test
    fun rootSuInPathFires() = assertEquals(fired, RootProbe.run(FakeProbeEnv(files = setOf("/system/xbin/su"))))

    @Test
    fun rootTestKeysFires() = assertEquals(fired, RootProbe.run(FakeProbeEnv(props = mapOf("ro.build.tags" to "test-keys"))))

    @Test
    fun rootMagiskMountFires() =
        assertEquals(fired, RootProbe.run(FakeProbeEnv(texts = mapOf("/proc/self/mounts" to "tmpfs /sbin/.magisk tmpfs rw 0 0"))))

    @Test
    fun rootCleanWhenNothingFound() =
        assertEquals(clean, RootProbe.run(FakeProbeEnv(props = mapOf("ro.build.tags" to "release-keys"))))

    @Test
    fun rootThrowingReadsAreUnavailable() = assertEquals(unavailable, RootProbe.run(ThrowingProbeEnv()))

    @Test
    fun rootEvidenceSurvivesAnotherCheckThrowing() {
        val env = object : FakeProbeEnv(files = setOf("/system/xbin/su")) {
            override fun prop(name: String): String? = throw SecurityException("denied")
        }
        assertEquals(fired, RootProbe.run(env))
    }

    @Test
    fun hookFridaAgentInMapsFires() =
        assertEquals(fired, HookProbe.run(FakeProbeEnv(texts = mapOf("/proc/self/maps" to "7f00 r-xp /data/local/tmp/frida-agent-64.so"))))

    @Test
    fun hookXposedClassFires() =
        assertEquals(fired, HookProbe.run(FakeProbeEnv(classes = setOf("de.robv.android.xposed.XposedBridge"))))

    @Test
    fun hookFridaPortFires() = assertEquals(fired, HookProbe.run(FakeProbeEnv(frida = true)))

    @Test
    fun hookClean() = assertEquals(clean, HookProbe.run(FakeProbeEnv(texts = mapOf("/proc/self/maps" to "7f00 r-xp /system/lib/libc.so"))))

    @Test
    fun hookThrowingIsUnavailable() = assertEquals(unavailable, HookProbe.run(ThrowingProbeEnv()))

    @Test
    fun emulatorQemuFires() = assertEquals(fired, EmulatorProbe.run(FakeProbeEnv(props = mapOf("ro.kernel.qemu" to "1"))))

    @Test
    fun emulatorRanchuFires() = assertEquals(fired, EmulatorProbe.run(FakeProbeEnv(props = mapOf("ro.hardware" to "ranchu"))))

    @Test
    fun emulatorClean() = assertEquals(clean, EmulatorProbe.run(FakeProbeEnv(props = mapOf("ro.hardware" to "qcom"))))

    @Test
    fun emulatorThrowingIsUnavailable() = assertEquals(unavailable, EmulatorProbe.run(ThrowingProbeEnv()))

    @Test
    fun debuggerConnectedFires() = assertEquals(fired, DebuggerProbe.run(FakeProbeEnv(debugger = true)))

    @Test
    fun debuggerDebuggableAppFires() = assertEquals(fired, DebuggerProbe.run(FakeProbeEnv(debuggable = true)))

    @Test
    fun debuggerClean() = assertEquals(clean, DebuggerProbe.run(FakeProbeEnv()))

    @Test
    fun debuggerThrowingIsUnavailable() = assertEquals(unavailable, DebuggerProbe.run(ThrowingProbeEnv()))

    @Test
    fun devoptsFires() {
        assertEquals(fired, DevOptsProbe.run(FakeProbeEnv(settings = mapOf("development_settings_enabled" to "1"))))
        assertEquals(fired, DevOptsProbe.run(FakeProbeEnv(settings = mapOf("adb_enabled" to "1"))))
    }

    @Test
    fun devoptsClean() =
        assertEquals(clean, DevOptsProbe.run(FakeProbeEnv(settings = mapOf("development_settings_enabled" to "0", "adb_enabled" to "0"))))

    @Test
    fun devoptsThrowingIsUnavailable() = assertEquals(unavailable, DevOptsProbe.run(ThrowingProbeEnv()))

    @Test
    fun mitmUserCaFires() = assertEquals(fired, MitmProbe.run(FakeProbeEnv(aliases = listOf("system:abc", "user:deadbeef.0"))))

    @Test
    fun mitmProxyFires() = assertEquals(fired, MitmProbe.run(FakeProbeEnv(proxy = true)))

    @Test
    fun mitmClean() = assertEquals(clean, MitmProbe.run(FakeProbeEnv(aliases = listOf("system:abc"))))

    @Test
    fun mitmThrowingIsUnavailable() = assertEquals(unavailable, MitmProbe.run(ThrowingProbeEnv()))

    @Test
    fun vpnThreeStates() {
        assertEquals(fired, VpnProbe.run(FakeProbeEnv(vpn = true)))
        assertEquals(clean, VpnProbe.run(FakeProbeEnv(vpn = false)))
        assertEquals(unavailable, VpnProbe.run(FakeProbeEnv(vpn = null)))
    }

    @Test
    fun mockLocationThreeStates() {
        assertEquals(fired, MockLocationProbe.run(FakeProbeEnv(mock = true)))
        assertEquals(clean, MockLocationProbe.run(FakeProbeEnv(mock = false)))
        assertEquals(unavailable, MockLocationProbe.run(FakeProbeEnv(mock = null)))
    }

    @Test
    fun cloneStandardPathIsClean() = assertEquals(clean, CloneProbe.run(FakeProbeEnv()))

    @Test
    fun cloneLegacyDataPathIsClean() = assertEquals(clean, CloneProbe.run(FakeProbeEnv(data = "/data/data/com.x")))

    @Test
    fun cloneVirtualContainerPathFires() =
        assertEquals(fired, CloneProbe.run(FakeProbeEnv(data = "/data/user/0/com.lbe.parallel/parallel/0/com.x")))

    @Test
    fun cloneUserIds() {
        assertEquals(fired, CloneProbe.run(FakeProbeEnv(uidValue = 999_10123)))
        assertEquals(fired, CloneProbe.run(FakeProbeEnv(uidValue = 95_10123)))
        assertEquals(clean, CloneProbe.run(FakeProbeEnv(uidValue = 10_10123, data = "/data/user/10/com.x")))
    }

    @Test
    fun cloneThrowingPropagatesToTheCollector() {
        val result = runCatching { CloneProbe.run(ThrowingProbeEnv()) }
        assertEquals(true, result.isFailure)
    }
}
