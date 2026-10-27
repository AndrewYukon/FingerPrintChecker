import DeviceCheck
import Foundation
#if os(macOS)
import IOKit
#else
import UIKit
#endif

/// What the collector produced: the final components (DeviceCheck hash included, so it is sealed)
/// and the DeviceCheck token to send as the top-level `deviceCheckToken`.
struct CollectedSignals: Sendable {
    let components: [FPComponent]
    let deviceCheckToken: String?
}

protocol SignalCollecting: Sendable {
    func collect(useDeviceCheck: Bool) async -> CollectedSignals
}

struct SystemSignalCollector: SignalCollecting {
    static let deviceCheckTimeout = 8.0
    /// `false` sends the "all unavailable" value instead of running probes (``FPConfig/integrityProbes``).
    var integrityProbes = true

    func collect(useDeviceCheck: Bool) async -> CollectedSignals {
        let platform = FPPlatform.current
        var raw = RawSignals(
            keychainId: KeychainIdentity.load(),
            timezone: TimeZone.current.identifier,
            osVersion: Self.osVersion())
        #if os(macOS)
        raw.platformUuid = Self.platformUUID()
        raw.model = Self.sysctlString("hw.model")
        #else
        raw.idfv = await MainActor.run { UIDevice.current.identifierForVendor?.uuidString }
        raw.model = Self.machine()
        raw.simulator = Self.isSimulator
        #endif
        raw.integrity = integrityProbes
            ? await IntegrityProbes.collect(env: SystemProbeEnvironment(), platform: platform)
            : IntegrityProbes.disabled(platform: platform)
        if useDeviceCheck { raw.deviceCheckToken = await Self.deviceCheckToken() }
        return CollectedSignals(
            components: ComponentRules.build(platform: platform, raw: raw),
            deviceCheckToken: raw.deviceCheckToken.flatMap { $0.isEmpty ? nil : $0 })
    }

    static func osVersion() -> String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }

    #if !os(macOS)
    static var isSimulator: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    static func machine() -> String? {
        var info = utsname()
        uname(&info)
        let machine = withUnsafeBytes(of: &info.machine) { buffer in
            String(decoding: buffer.prefix(while: { $0 != 0 }), as: UTF8.self)
        }
        return machine.isEmpty ? nil : machine
    }
    #endif

    #if os(macOS)
    static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 1 else { return nil }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }
        let value = String(cString: buffer)
        return value.isEmpty ? nil : value
    }

    static func platformUUID() -> String? {
        let port: mach_port_t
        if #available(macOS 12.0, *) { port = kIOMainPortDefault } else { port = 0 }
        let service = IOServiceGetMatchingService(port, IOServiceMatching("IOPlatformExpertDevice"))
        guard service != 0 else { return nil }
        defer { IOObjectRelease(service) }
        let property = IORegistryEntryCreateCFProperty(
            service, "IOPlatformUUID" as CFString, kCFAllocatorDefault, 0)
        return property?.takeRetainedValue() as? String
    }
    #endif

    /// Base64 DeviceCheck token, or `nil` when unsupported, failed or too slow.
    static func deviceCheckToken() async -> String? {
        guard DCDevice.current.isSupported else { return nil }
        let result: String?? = await withDeadline(seconds: deviceCheckTimeout) {
            await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
                DCDevice.current.generateToken { data, error in
                    if let data, error == nil {
                        continuation.resume(returning: data.base64EncodedString())
                    } else {
                        continuation.resume(returning: nil)
                    }
                }
            }
        }
        return result ?? nil
    }
}
