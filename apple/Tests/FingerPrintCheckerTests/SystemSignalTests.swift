import XCTest
@testable import FingerPrintChecker

final class SystemSignalTests: XCTestCase {
    func testOSVersionHasThreeParts() {
        let parts = SystemSignalCollector.osVersion().split(separator: ".")
        XCTAssertEqual(parts.count, 3)
        XCTAssertLessThanOrEqual(SystemSignalCollector.osVersion().count, ComponentRules.maxOSVersion)
    }

    #if os(macOS)
    func testMacPlatformUUIDAndModelAreReadable() throws {
        let uuid = try XCTUnwrap(SystemSignalCollector.platformUUID())
        XCTAssertEqual(ComponentRules.normalizeUUID(uuid), uuid)
        let model = try XCTUnwrap(SystemSignalCollector.sysctlString("hw.model"))
        XCTAssertLessThanOrEqual(model.count, ComponentRules.maxModel)
    }
    #endif
}
