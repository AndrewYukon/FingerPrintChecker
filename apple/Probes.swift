import Foundation

/// Runs independent checks: fired if any fires, unavailable if none fired but one could not run, else clean.
private func anyOf(_ checks: [() throws -> Bool]) -> ProbeResult {
    var failed = false
    for check in checks {
        do {
            if try check() { return .fired }
        } catch {
            failed = true
        }
    }
    return failed ? .unavailable : .clean
}

private func tri(_ value: Bool?) -> ProbeResult {
    switch value {
    case .none: return .unavailable
    case .some(true): return .fired
    case .some(false): return .clean
    }
}

private let fridaPort: UInt16 = 27042
private let portTimeout: TimeInterval = 0.1

/// Paths that exist only on jailbroken devices. Deliberately no `/bin/bash` or `/etc/apt`: the simulator
/// sees the host Mac's filesystem.
private let jailbreakPaths = [
    "/var/jb", "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib", "/private/var/lib/apt", "/var/lib/cydia",
    "/usr/lib/libsubstitute.dylib", "/usr/libexec/sftp-server",
]

private let hookImageMarkers = ["fridagadget", "frida-gadget", "frida-agent", "mobilesubstrate", "cydiasubstrate", "libhooker"]

struct JailbreakProbe: Probe {
    let code = "jailbreak"
    func run(_ env: ProbeEnvironment) throws -> ProbeResult {
        anyOf([
            { jailbreakPaths.contains { env.fileExists($0) } },
            { env.canWriteOutsideSandbox() },
        ])
    }
}

struct HookProbe: Probe {
    let code = "hook"
    func run(_ env: ProbeEnvironment) throws -> ProbeResult {
        anyOf([
            { env.loadedImageNames().contains { name in
                let lower = name.lowercased()
                return hookImageMarkers.contains { lower.contains($0) }
            } },
            { env.canConnectLocal(port: fridaPort, timeout: portTimeout) },
        ])
    }
}

struct EmulatorProbe: Probe {
    let code = "emulator"
    func run(_ env: ProbeEnvironment) throws -> ProbeResult {
        anyOf([{ !(env.environment("SIMULATOR_DEVICE_NAME") ?? "").isEmpty }])
    }
}

struct DebuggerProbe: Probe {
    let code = "debugger"
    func run(_ env: ProbeEnvironment) throws -> ProbeResult { anyOf([{ env.isTraced() }]) }
}

struct MitmProbe: Probe {
    let code = "mitm"
    func run(_ env: ProbeEnvironment) throws -> ProbeResult {
        guard let proxy = env.proxySettings() else { return .unavailable }
        let on = ["HTTPEnable", "HTTPSEnable"].contains { (proxy[$0] as? NSNumber)?.intValue == 1 }
        return on ? .fired : .clean
    }
}

/// Version 1 counts only legacy tunnel interfaces. `utun*` is also used by iCloud Private Relay, Tailscale and
/// system services, so it is not evidence by itself and is deliberately ignored here (M21).
struct VpnProbe: Probe {
    let code = "vpn"
    static let prefixes = ["ipsec", "ppp", "tap", "tun"]
    func run(_ env: ProbeEnvironment) throws -> ProbeResult {
        guard let scoped = env.proxySettings()?["__SCOPED__"] as? [String: Any] else { return .unavailable }
        return scoped.keys.contains { key in Self.prefixes.contains { key.hasPrefix($0) } } ? .fired : .clean
    }
}

struct MockLocationProbe: Probe {
    let code = "mock_location"
    func run(_ env: ProbeEnvironment) throws -> ProbeResult { tri(env.locationSimulated()) }
}

let allProbes: [Probe] = [
    JailbreakProbe(), HookProbe(), EmulatorProbe(), DebuggerProbe(), MitmProbe(), VpnProbe(), MockLocationProbe(),
]
