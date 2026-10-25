import XCTest
@testable import FingerPrintChecker

final class SealedResultTests: XCTestCase {
    func testAnswerWithSealedResultExposesIt() {
        let v2 = Data(#"{"ok":true,"attestation":"fpa1.x","sealedResult":"fpsr1.payload.tag"}"#.utf8)
        guard case .success(let s2) = ResponseParser.parseIdentifyV2(v2, httpStatus: 200) else { return XCTFail() }
        XCTAssertEqual(s2.sealedResult, "fpsr1.payload.tag")
        let v1 = Data(#"{"ok":true,"visitorId":"i4_x","sealedResult":"fpsr1.payload.tag"}"#.utf8)
        guard case .success(let s1) = ResponseParser.parseIdentify(v1, httpStatus: 200) else { return XCTFail() }
        XCTAssertEqual(s1.sealedResult, "fpsr1.payload.tag")
    }

    func testAnswerWithoutItIsNil() {
        let v2 = Data(#"{"ok":true,"attestation":"fpa1.x"}"#.utf8)
        guard case .success(let s2) = ResponseParser.parseIdentifyV2(v2, httpStatus: 200) else { return XCTFail() }
        XCTAssertNil(s2.sealedResult)
        let v1 = Data(#"{"ok":true,"visitorId":"i4_x"}"#.utf8)
        guard case .success(let s1) = ResponseParser.parseIdentify(v1, httpStatus: 200) else { return XCTFail() }
        XCTAssertNil(s1.sealedResult)
    }

    func testNonStringOrEmptyIsNil() {
        for bad in ["null", "5", "{}", "\"\""] {
            let v2 = Data(#"{"ok":true,"attestation":"fpa1.x","sealedResult":"#.utf8) + Data(bad.utf8) + Data("}".utf8)
            guard case .success(let s2) = ResponseParser.parseIdentifyV2(v2, httpStatus: 200) else { return XCTFail(bad) }
            XCTAssertNil(s2.sealedResult, bad)
            let v1 = Data(#"{"ok":true,"visitorId":"i4_x","sealedResult":"#.utf8) + Data(bad.utf8) + Data("}".utf8)
            guard case .success(let s1) = ResponseParser.parseIdentify(v1, httpStatus: 200) else { return XCTFail(bad) }
            XCTAssertNil(s1.sealedResult, bad)
        }
    }
}
