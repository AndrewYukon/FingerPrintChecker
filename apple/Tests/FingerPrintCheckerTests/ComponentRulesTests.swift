import XCTest
@testable import FingerPrintChecker

final class ComponentRulesTests: XCTestCase {
    func testValidatorAcceptsVectorComponents() throws {
        let vectors = try Vectors.load()
        for c in vectors.cases {
            guard let platform = FPPlatform(rawValue: c.platform) else { continue }
            let components = c.components.map { FPComponent(key: $0.key, value: $0.value) }
            XCTAssertEqual(ComponentRules.validate(platform: platform, components: components), [], c.name)
        }
    }

    func testValidatorRejectsBadInput() {
        let id = FPComponent(key: "ios.keychainId", value: "A1B2C3D4-E5F6-4711-8899-AABBCCDDEEFF")
        func errors(_ extra: [FPComponent]) -> [String] {
            ComponentRules.validate(platform: .ios, components: [id] + extra)
        }
        XCTAssertFalse(errors([id]).isEmpty, "duplicate")
        XCTAssertFalse(errors([FPComponent(key: "macos.model", value: "x")]).isEmpty, "foreign key")
        XCTAssertFalse(errors([FPComponent(key: "ios.idfv", value: "00000000-0000-0000-0000-000000000000")]).isEmpty)
        XCTAssertFalse(errors([FPComponent(key: "ios.simulator", value: "yes")]).isEmpty)
        XCTAssertFalse(errors([FPComponent(key: "ios.deviceCheck", value: "ABC")]).isEmpty)
        XCTAssertFalse(errors([FPComponent(key: "ios.model", value: String(repeating: "m", count: 65))]).isEmpty)
        XCTAssertFalse(errors([FPComponent(key: "ios.osVersion", value: String(repeating: "1", count: 33))]).isEmpty)
        XCTAssertTrue(ComponentRules.validate(platform: .ios, components: [
            FPComponent(key: "ios.model", value: "iPhone17,1"),
        ]).contains("no identity key"))
        XCTAssertTrue(errors([]).isEmpty)
    }

    func testBuildOmitsUnobtainableAndDegenerateValues() {
        let raw = RawSignals(
            keychainId: "A1B2C3D4-E5F6-4711-8899-AABBCCDDEEFF",
            idfv: "00000000-0000-0000-0000-000000000000",
            timezone: "Europe/Berlin", model: "iPhone17,1", osVersion: "26.1.0", simulator: false)
        let keys = ComponentRules.build(platform: .ios, raw: raw).map(\.key)
        XCTAssertEqual(keys.sorted(), ["ios.keychainId", "ios.model", "ios.osVersion", "ios.simulator", "ios.timezone"])
        XCTAssertFalse(ComponentRules.build(platform: .ios, raw: RawSignals(idfv: nil)).contains { $0.key == "ios.idfv" })
        XCTAssertTrue(ComponentRules.build(platform: .ios, raw: RawSignals()).isEmpty)
    }

    func testBuildMacOSUsesMacKeysAndNoSimulator() {
        let raw = RawSignals(
            keychainId: "11111111-2222-4333-8444-555555555555",
            platformUuid: "5F2A9C1E-3B4D-4E6F-8A7B-9C0D1E2F3A4B", model: "Mac15,3", simulator: true)
        let keys = ComponentRules.build(platform: .macos, raw: raw).map(\.key).sorted()
        XCTAssertEqual(keys, ["macos.keychainId", "macos.model", "macos.platformUuid"])
    }

    func testBuildTruncatesLongValues() {
        let raw = RawSignals(
            idfv: "0F1E2D3C-4B5A-4968-8778-695A4B3C2D1E",
            model: String(repeating: "m", count: 100), osVersion: String(repeating: "9", count: 50))
        let built = ComponentRules.build(platform: .ios, raw: raw)
        XCTAssertEqual(built.first { $0.key == "ios.model" }?.value.count, 64)
        XCTAssertEqual(built.first { $0.key == "ios.osVersion" }?.value.count, 32)
    }

    func testDeviceCheckComponentIsHashOfBase64String() {
        let token = "dGVzdC10b2tlbg=="
        // sha256 of the UTF-8 bytes of the base64 string itself (not of the decoded token), computed independently.
        let expected = "1bc401f4175397f48cd6a17a2395e295101dad5741ec5e7e58322482622e44cf"
        XCTAssertEqual(ComponentRules.deviceCheckHash(token: token), expected)
        let raw = RawSignals(idfv: "0F1E2D3C-4B5A-4968-8778-695A4B3C2D1E", deviceCheckToken: token)
        XCTAssertEqual(
            ComponentRules.build(platform: .ios, raw: raw).first { $0.key == "ios.deviceCheck" }?.value,
            expected)
    }
}
