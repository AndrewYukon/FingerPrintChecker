import XCTest
@testable import FingerPrintChecker

private final class RecordingTransport: HTTPTransport, @unchecked Sendable {
    var v1Answer = #"{"ok":true,"visitorId":"i4_x","isNew":true,"eventId":"ev_0123456789ABCDEFGHJK","attestation":{"token":"fpa1.x"}}"#
    var v2Answer = #"{"ok":true,"protocolVersion":2,"attestation":"fpa1.x","eventId":"ev_0123456789ABCDEFGHJK"}"#
    private(set) var requests = [URLRequest]()

    func send(_ request: URLRequest) async throws -> (data: Data, status: Int) {
        requests.append(request)
        switch request.url?.path {
        case "/v1/challenge": return (Data(#"{"nonce":"n1"}"#.utf8), 200)
        case "/v2/challenge": return (Data(#"{"ok":true,"challenge":"v4.c1"}"#.utf8), 200)
        case "/v1/identify": return (Data(v1Answer.utf8), 200)
        default: return (Data(v2Answer.utf8), 200)
        }
    }

    var last: [String: Any] {
        get throws {
            let request = try XCTUnwrap(requests.last)
            return try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as? [String: Any])
        }
    }
}

private struct StubCollector: SignalCollecting {
    func collect(useDeviceCheck: Bool) async -> CollectedSignals {
        CollectedSignals(
            components: [FPComponent(key: "ios.keychainId", value: "A1B2C3D4-E5F6-4711-8899-AABBCCDDEEFF")],
            deviceCheckToken: nil)
    }
}

final class EventFieldsTests: XCTestCase {
    private func checker(_ transport: RecordingTransport) -> FingerPrintChecker {
        FingerPrintChecker(
            config: FPConfig(publishableKey: "pk_test", sealKey: "seal"),
            platform: .ios, transport: transport, collector: StubCollector(), appAttest: nil)
    }

    private func reason(_ result: FPResultV2) -> String? {
        if case .failure(let reason, _) = result { return reason }
        return nil
    }

    // MARK: sent when given, absent when not

    func testV2SendsFieldsWhenGiven() async throws {
        let transport = RecordingTransport()
        let result = await checker(transport).identify(
            intentToken: "t", linkedId: "order_42", tags: ["page": "checkout", "n": [1, 2], "o": ["k": NSNull()]])
        guard case .success(let success) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(success.eventId, "ev_0123456789ABCDEFGHJK")
        let json = try transport.last
        XCTAssertEqual(json["linkedId"] as? String, "order_42")
        let tags = try XCTUnwrap(json["tags"] as? [String: Any])
        XCTAssertEqual(tags["page"] as? String, "checkout")
        XCTAssertEqual((tags["n"] as? [Int]), [1, 2])
    }

    func testV2SendsNothingWhenNotGiven() async throws {
        let transport = RecordingTransport()
        _ = await checker(transport).identify(intentToken: "t")
        var json = try transport.last
        XCTAssertNil(json["linkedId"])
        XCTAssertNil(json["tags"])
        // an explicit nil is the same as absent
        _ = await checker(transport).identify(intentToken: "t", linkedId: nil, tags: nil)
        json = try transport.last
        XCTAssertNil(json["linkedId"])
        XCTAssertNil(json["tags"])
    }

    func testV1SendsFieldsAndKeepsTheSealUnchanged() async throws {
        let plain = RecordingTransport()
        let plainResult = await checker(plain).identify()
        let withFields = RecordingTransport()
        let result = await checker(withFields).identify(linkedId: "u_1", tags: ["a": 1])
        guard case .success(let success) = result, case .success(let plainSuccess) = plainResult else {
            return XCTFail("\(result) \(plainResult)")
        }
        XCTAssertEqual(success.eventId, "ev_0123456789ABCDEFGHJK")
        XCTAssertEqual(plainSuccess.eventId, "ev_0123456789ABCDEFGHJK")
        let json = try withFields.last, base = try plain.last
        XCTAssertEqual(json["linkedId"] as? String, "u_1")
        XCTAssertNil(base["linkedId"])
        XCTAssertNil(base["tags"])
        // same nonce and components: the seal does not cover the event fields
        XCTAssertEqual(json["sig"] as? String, base["sig"] as? String)
    }

    // MARK: invalid values fail with zero network calls

    func testInvalidValuesAreRefusedBeforeAnyRequest() async {
        let deep: [String: Any] = ["a": ["b": ["c": ["d": 1]]]]
        let arrayAtLevelThree: [String: Any] = ["a": ["b": [1]]]
        let big: [String: Any] = ["k": String(repeating: "a", count: 4096)]
        let cases: [(String?, [String: Any]?, String)] = [
            ("", nil, "invalid_linked_id"),
            (String(repeating: "a", count: 257), nil, "invalid_linked_id"),
            ("a\nb", nil, "invalid_linked_id"),
            ("a\u{7f}b", nil, "invalid_linked_id"),
            (nil, deep, "invalid_tags"),
            (nil, arrayAtLevelThree, "invalid_tags"),
            (nil, big, "invalid_tags"),
            (nil, ["x": Double.nan], "invalid_tags"),
            (nil, ["x": Date()], "invalid_tags"),
        ]
        for (linkedId, tags, expected) in cases {
            let v2 = RecordingTransport()
            let v2Result = await checker(v2).identify(intentToken: "t", linkedId: linkedId, tags: tags)
            XCTAssertEqual(reason(v2Result), expected)
            XCTAssertEqual(v2.requests.count, 0, "v2 \(expected)")

            let v1 = RecordingTransport()
            let v1Result = await checker(v1).identify(linkedId: linkedId, tags: tags)
            guard case .failure(let r, let status) = v1Result else { XCTFail("\(v1Result)"); continue }
            XCTAssertEqual([r, String(status)], [expected, "0"])
            XCTAssertEqual(v1.requests.count, 0, "v1 \(expected)")
        }
    }

    func testBoundariesAreAccepted() {
        XCTAssertNoThrow(try EventFields.validate(linkedId: "a", tags: nil).get())
        XCTAssertNoThrow(try EventFields.validate(linkedId: String(repeating: "a", count: 256), tags: nil).get())
        XCTAssertNoThrow(try EventFields.validate(linkedId: nil, tags: ["a": ["b": ["c": 1]]]).get())
        XCTAssertNoThrow(try EventFields.validate(linkedId: nil, tags: ["l": [1, "x", true, NSNull()]]).get())
        // {"k":"..."} has 8 bytes of framing; slashes are not escaped
        XCTAssertNoThrow(try EventFields.validate(linkedId: nil, tags: ["k": String(repeating: "a", count: 4088)]).get())
        XCTAssertNoThrow(try EventFields.validate(linkedId: nil, tags: ["k": String(repeating: "/", count: 4088)]).get())
        XCTAssertThrowsError(try EventFields.validate(linkedId: nil, tags: ["k": String(repeating: "a", count: 4089)]).get())
        // 1366 three-byte characters are 4098 bytes
        XCTAssertThrowsError(try EventFields.validate(linkedId: nil, tags: ["k": String(repeating: "\u{20ac}", count: 1366)]).get())
    }

    // MARK: eventId parsing

    func testEventIdParsing() {
        let v2 = Data(#"{"ok":true,"attestation":"fpa1.x","eventId":"ev_0123456789ABCDEFGHJK"}"#.utf8)
        guard case .success(let s2) = ResponseParser.parseIdentifyV2(v2, httpStatus: 200) else { return XCTFail() }
        XCTAssertEqual(s2.eventId, "ev_0123456789ABCDEFGHJK")
        let old = Data(#"{"ok":true,"attestation":"fpa1.x"}"#.utf8)
        guard case .success(let s3) = ResponseParser.parseIdentifyV2(old, httpStatus: 200) else { return XCTFail() }
        XCTAssertNil(s3.eventId)
        let v1Old = Data(#"{"ok":true,"visitorId":"i4_x","eventId":null}"#.utf8)
        guard case .success(let s4) = ResponseParser.parseIdentify(v1Old, httpStatus: 200) else { return XCTFail() }
        XCTAssertNil(s4.eventId)
    }
}
