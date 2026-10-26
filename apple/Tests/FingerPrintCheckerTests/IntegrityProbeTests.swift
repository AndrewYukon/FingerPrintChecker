import XCTest
@testable import FingerPrintChecker

/// Scriptable environment. Every reading defaults to "nothing suspicious".
private final class FakeEnv: ProbeEnvironment, @unchecked Sendable {
    var files = Set<String>()
    var writable = false
    var images = [String]()
    var openPorts = Set<UInt16>()
    var vars = [String: String]()
    var traced: Bool? = false
    var connectFails = false
    var proxy: [String: Any]? = ["HTTPEnable": 0, "__SCOPED__": ["en0": [String: Any]()]]
    var simulated: Bool?

    func fileExists(_ path: String) -> Bool { files.contains(path) }
    func canWriteOutsideSandbox() -> Bool { writable }
    func loadedImageNames() -> [String] { images }
    func canConnectLocal(port: UInt16, timeout: TimeInterval) -> Bool? { connectFails ? nil : openPorts.contains(port) }
    func environment(_ name: String) -> String? { vars[name] }
    func isTraced() -> Bool? { traced }
    func proxySettings() -> [String: Any]? { proxy }
    func locationSimulated() -> Bool? { simulated }
}

private struct FixedProbe: Probe {
    let code: String
    let outcome: ProbeResult
    func run(_ env: ProbeEnvironment) throws -> ProbeResult { outcome }
}

private struct ThrowingProbe: Probe {
    struct Boom: Error {}
    let code: String
    func run(_ env: ProbeEnvironment) throws -> ProbeResult { throw Boom() }
}

/// Blocks until `release()`; tests release it at the end so no thread is left hanging.
private final class BlockingProbe: Probe, @unchecked Sendable {
    let code: String
    private let gate = DispatchSemaphore(value: 0)
    init(code: String) { self.code = code }
    func run(_ env: ProbeEnvironment) throws -> ProbeResult { gate.wait(); return .fired }
    func release() { gate.signal() }
}

final class IntegrityProbeTests: XCTestCase {
    private func run(_ probe: Probe, _ env: FakeEnv) throws -> ProbeResult { try probe.run(env) }

    // MARK: jailbreak
    func testJailbreakFiredByKnownPath() throws {
        let env = FakeEnv(); env.files = ["/var/jb"]
        XCTAssertEqual(try run(JailbreakProbe(), env), .fired)
    }
    func testJailbreakFiredByWritableOutsideSandbox() throws {
        let env = FakeEnv(); env.writable = true
        XCTAssertEqual(try run(JailbreakProbe(), env), .fired)
    }
    func testJailbreakCleanWhenNothingFound() throws {
        XCTAssertEqual(try run(JailbreakProbe(), FakeEnv()), .clean)
    }

    #if os(macOS)
    /// The simulator sees the host filesystem, so a path that exists on a stock Mac would fire on every run.
    func testJailbreakPathsAbsentOnStockMac() {
        for path in jailbreakPaths {
            XCTAssertFalse(FileManager.default.fileExists(atPath: path), path)
        }
    }
    #endif

    // MARK: hook
    func testHookFiredByImageNames() throws {
        for name in ["/usr/lib/FridaGadget.dylib", "/Library/MobileSubstrate/MobileSubstrate.dylib", "/var/jb/usr/lib/libhooker.dylib"] {
            let env = FakeEnv(); env.images = ["/usr/lib/libSystem.B.dylib", name]
            XCTAssertEqual(try run(HookProbe(), env), .fired, name)
        }
    }
    func testHookFiredByFridaPort() throws {
        let env = FakeEnv(); env.openPorts = [27042]
        XCTAssertEqual(try run(HookProbe(), env), .fired)
    }
    func testHookCleanOtherwise() throws {
        let env = FakeEnv(); env.images = ["/usr/lib/libSystem.B.dylib"]
        XCTAssertEqual(try run(HookProbe(), env), .clean)
    }

    // MARK: emulator, debugger
    func testEmulatorFiredBySimulatorVariable() throws {
        let env = FakeEnv(); env.vars["SIMULATOR_DEVICE_NAME"] = "iPhone 16"
        XCTAssertEqual(try run(EmulatorProbe(), env), .fired)
        XCTAssertEqual(try run(EmulatorProbe(), FakeEnv()), .clean)
    }
    func testDebuggerFiredWhenTraced() throws {
        let env = FakeEnv(); env.traced = true
        XCTAssertEqual(try run(DebuggerProbe(), env), .fired)
        XCTAssertEqual(try run(DebuggerProbe(), FakeEnv()), .clean)
    }

    func testFailedReadsAreUnavailableNotClean() throws {
        let traceFail = FakeEnv(); traceFail.traced = nil
        XCTAssertEqual(try run(DebuggerProbe(), traceFail), .unavailable)
        let connectFail = FakeEnv(); connectFail.connectFails = true
        XCTAssertEqual(try run(HookProbe(), connectFail), .unavailable)
        connectFail.images = ["/usr/lib/FridaGadget.dylib"]
        XCTAssertEqual(try run(HookProbe(), connectFail), .fired)
    }

    // MARK: mitm
    func testMitmFiredByHttpProxy() throws {
        let env = FakeEnv(); env.proxy = ["HTTPEnable": 1]
        XCTAssertEqual(try run(MitmProbe(), env), .fired)
        env.proxy = ["HTTPEnable": 0, "HTTPSEnable": 1]
        XCTAssertEqual(try run(MitmProbe(), env), .fired)
    }
    func testMitmUnavailableWithoutProxySettings() throws {
        let env = FakeEnv(); env.proxy = nil
        XCTAssertEqual(try run(MitmProbe(), env), .unavailable)
        XCTAssertEqual(try run(MitmProbe(), FakeEnv()), .clean)
    }

    // MARK: vpn (M21)
    func testVpnFiredByLegacyTunnelInterfaces() throws {
        for iface in ["ppp0", "tun0", "tap0"] {
            let env = FakeEnv(); env.proxy = ["__SCOPED__": [iface: [String: Any]()]]
            XCTAssertEqual(try run(VpnProbe(), env), .fired, iface)
        }
    }
    func testVpnVersionOneDoesNotCountUtun() throws {
        let env = FakeEnv(); env.proxy = ["__SCOPED__": ["utun3": [String: Any]()]]
        XCTAssertEqual(try run(VpnProbe(), env), .clean)
        env.proxy = ["__SCOPED__": ["en0": [String: Any](), "pdp_ip0": [String: Any]()]]
        XCTAssertEqual(try run(VpnProbe(), env), .clean)
    }
    func testVpnUnavailableWhenInterfacesCannotBeSeen() throws {
        let env = FakeEnv(); env.proxy = nil
        XCTAssertEqual(try run(VpnProbe(), env), .unavailable)
        env.proxy = ["HTTPEnable": 0]
        XCTAssertEqual(try run(VpnProbe(), env), .unavailable)
    }

    // MARK: mock_location
    func testMockLocationIsThreeState() throws {
        let env = FakeEnv()
        XCTAssertEqual(try run(MockLocationProbe(), env), .unavailable)
        env.simulated = true
        XCTAssertEqual(try run(MockLocationProbe(), env), .fired)
        env.simulated = false
        XCTAssertEqual(try run(MockLocationProbe(), env), .clean)
    }

    // MARK: codes and encoding
    func testCodeSets() {
        XCTAssertEqual(IntegrityProbes.codes(for: .ios), ["jailbreak", "hook", "emulator", "debugger", "mitm", "vpn", "mock_location"])
        XCTAssertEqual(IntegrityProbes.codes(for: .macos), ["debugger", "hook"])
    }
    func testEncodeKeepsCodeOrderAndMissingIsUnavailable() {
        let value = IntegrityProbes.encode(["vpn": .fired, "hook": .fired, "debugger": .clean], platform: .ios)
        XCTAssertEqual(value, "1:hook,vpn:jailbreak,emulator,mitm,mock_location")
    }
    func testMacOSValueNeverMentionsIosCodes() {
        let value = IntegrityProbes.encode(["hook": .fired, "jailbreak": .fired], platform: .macos)
        XCTAssertEqual(value, "1:hook:debugger")
        XCTAssertEqual(IntegrityProbes.disabled(platform: .macos), "1::debugger,hook")
    }
    func testDisabledValue() {
        XCTAssertEqual(IntegrityProbes.disabled(platform: .ios), "1::jailbreak,hook,emulator,debugger,mitm,vpn,mock_location")
    }
    func testEveryEncodedValueIsAcceptedByTheValidator() {
        for platform in [FPPlatform.ios, .macos] {
            for value in [IntegrityProbes.disabled(platform: platform), IntegrityProbes.encode([:], platform: platform)] {
                let comps = [FPComponent(key: platform.key("keychainId"), value: "A1B2C3D4-E5F6-4711-8899-AABBCCDDEEFF"),
                             FPComponent(key: platform.key("integrity"), value: value)]
                XCTAssertEqual(ComponentRules.validate(platform: platform, components: comps), [], value)
            }
        }
    }

    // MARK: collector
    private func collect(_ probes: [Probe], timeout: TimeInterval = 5) async -> String {
        await IntegrityProbes.collect(env: FakeEnv(), platform: .ios, probes: probes, timeout: timeout)
    }

    func testCollectorReportsEachProbeResult() async {
        let value = await collect([
            FixedProbe(code: "jailbreak", outcome: .fired), FixedProbe(code: "hook", outcome: .clean),
            FixedProbe(code: "vpn", outcome: .unavailable),
        ])
        XCTAssertEqual(value, "1:jailbreak:emulator,debugger,mitm,vpn,mock_location")
    }

    func testThrowingProbeIsUnavailableAndOthersSurvive() async {
        let value = await collect([ThrowingProbe(code: "hook"), FixedProbe(code: "jailbreak", outcome: .fired)])
        XCTAssertTrue(value.hasPrefix("1:jailbreak:hook,"), value)
    }

    func testSlowProbeBecomesUnavailableWithoutCostingOthers() async {
        let slow = BlockingProbe(code: "mitm")
        defer { slow.release() }
        let value = await collect([slow, FixedProbe(code: "debugger", outcome: .fired)], timeout: 0.5)
        XCTAssertEqual(value, "1:debugger:jailbreak,hook,emulator,mitm,vpn,mock_location")
    }

    func testLateProbeResultIsIgnoredAfterTheDeadline() async {
        let slow = BlockingProbe(code: "hook")
        let first = await collect([slow], timeout: 0.3)
        slow.release()
        XCTAssertTrue(first.contains("hook"), first)
        XCTAssertFalse(first.hasPrefix("1:hook"), first)
    }

    func testSystemCollectionOnThisMachineProducesAValidValue() async {
        let platform = FPPlatform.current
        let value = await IntegrityProbes.collect(env: SystemProbeEnvironment(), platform: platform, timeout: 5)
        let comps = [FPComponent(key: platform.key("keychainId"), value: "A1B2C3D4-E5F6-4711-8899-AABBCCDDEEFF"),
                     FPComponent(key: platform.key("integrity"), value: value)]
        XCTAssertEqual(ComponentRules.validate(platform: platform, components: comps), [], value)
        #if os(macOS)
        // Guards against every probe silently degrading to unavailable: on a Mac, debugger and hook run for real.
        XCTAssertEqual(value.split(separator: ":", omittingEmptySubsequences: false).count, 3, value)
        let unavailable = value.split(separator: ":", omittingEmptySubsequences: false)[2]
        XCTAssertEqual(unavailable, "", "macOS debugger/hook must be checked, not unavailable: \(value)")
        #endif
    }

    func testBuildIncludesIntegrityOnlyWhenValidAndPresent() {
        var raw = RawSignals(keychainId: "A1B2C3D4-E5F6-4711-8899-AABBCCDDEEFF")
        XCTAssertFalse(ComponentRules.build(platform: .ios, raw: raw).contains { $0.key == "ios.integrity" })
        raw.integrity = "1:hook:vpn"
        XCTAssertEqual(ComponentRules.build(platform: .ios, raw: raw).first { $0.key == "ios.integrity" }?.value, "1:hook:vpn")
        raw.integrity = "1:hook:hook"
        XCTAssertFalse(ComponentRules.build(platform: .ios, raw: raw).contains { $0.key == "ios.integrity" })
    }

    func testIntegrityKeysAreNotIdentity() {
        let errors = ComponentRules.validate(platform: .ios, components: [FPComponent(key: "ios.integrity", value: "1::")])
        XCTAssertTrue(errors.contains("no identity key"))
    }

    // MARK: runtime-resolved CoreLocation reader
    func testCachedLocationReaderThreeStates() {
        XCTAssertEqual(CachedLocationReader.simulated(manager: FakeManager(status: 4, simulated: true)), true)
        XCTAssertEqual(CachedLocationReader.simulated(manager: FakeManager(status: 3, simulated: false)), false)
        XCTAssertNil(CachedLocationReader.simulated(manager: FakeManager(status: 0, simulated: true)))
        XCTAssertNil(CachedLocationReader.simulated(manager: FakeManager(status: 4, simulated: nil)))
        XCTAssertNil(CachedLocationReader.simulated(manager: FakeManager(status: 4, simulated: true, hasLocation: false)))
        XCTAssertNil(CachedLocationReader.simulated(manager: NSObject()))  // no keys at all: no exception
    }
}

@objc private final class FakeSource: NSObject {
    @objc let isSimulatedBySoftware: Bool
    init(_ value: Bool) { isSimulatedBySoftware = value }
}

@objc private final class FakeFix: NSObject {
    @objc let sourceInformation: FakeSource?
    init(_ source: FakeSource?) { sourceInformation = source }
}

@objc private final class FakeManager: NSObject {
    @objc let authorizationStatus: Int
    @objc let location: FakeFix?
    init(status: Int, simulated: Bool?, hasLocation: Bool = true) {
        authorizationStatus = status
        location = hasLocation ? FakeFix(simulated.map(FakeSource.init)) : nil
    }
}
