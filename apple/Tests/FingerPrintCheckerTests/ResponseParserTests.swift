import XCTest
@testable import FingerPrintChecker

final class ResponseParserTests: XCTestCase {
    func testSuccessIncludingProofStatus() throws {
        let body = Data("""
        {"ok":true,"platform":"ios","visitorId":"i4_abc","identityConfidence":100,"trustScore":88,
         "trustDeductions":["tz_ip_mismatch"],"shadowDeductions":[],"rulesVersion":"n3","isNew":false,
         "attestation":"tok.en","proofStatus":"checked"}
        """.utf8)
        guard case .success(let s) = ResponseParser.parseIdentify(body, httpStatus: 200) else {
            return XCTFail("expected success")
        }
        XCTAssertEqual(s.visitorId, "i4_abc")
        XCTAssertEqual(s.trustScore, 88)
        XCTAssertEqual(s.identityConfidence, 100)
        XCTAssertFalse(s.isNew)
        XCTAssertEqual(s.attestation, "tok.en")
        XCTAssertEqual(s.trustDeductions, ["tz_ip_mismatch"])
        XCTAssertEqual(s.proofStatus, "checked")
        XCTAssertEqual(s.raw, body)
    }

    func testObjectAttestationIsReserialisedAndNullIsNil() {
        let object = Data(#"{"ok":true,"visitorId":"v","attestation":{"a":1}}"#.utf8)
        guard case .success(let s) = ResponseParser.parseIdentify(object, httpStatus: 200) else { return XCTFail() }
        XCTAssertEqual(s.attestation, #"{"a":1}"#)
        let null = Data(#"{"ok":true,"visitorId":"v","attestation":null}"#.utf8)
        guard case .success(let n) = ResponseParser.parseIdentify(null, httpStatus: 200) else { return XCTFail() }
        XCTAssertNil(n.attestation)
        XCTAssertNil(n.proofStatus)
    }

    func testFailureCarriesReasonAndStatus() {
        let body = Data(#"{"ok":false,"visitorId":null,"trustScore":0,"reason":"seal_invalid"}"#.utf8)
        XCTAssertEqual(
            ResponseParser.parseIdentify(body, httpStatus: 400), .failure(reason: "seal_invalid", httpStatus: 400))
    }

    func testGarbageAndMissingVisitorAreBadResponse() {
        XCTAssertEqual(
            ResponseParser.parseIdentify(Data("<html>".utf8), httpStatus: 502),
            .failure(reason: "bad_response", httpStatus: 502))
        XCTAssertEqual(
            ResponseParser.parseIdentify(Data(#"{"ok":true,"visitorId":null}"#.utf8), httpStatus: 200),
            .failure(reason: "bad_response", httpStatus: 200))
    }

    func testNonce() {
        XCTAssertEqual(ResponseParser.parseNonce(Data(#"{"nonce":"n1","expiresIn":300}"#.utf8)), "n1")
        XCTAssertNil(ResponseParser.parseNonce(Data(#"{"nonce":""}"#.utf8)))
        XCTAssertNil(ResponseParser.parseNonce(Data("x".utf8)))
    }
}
