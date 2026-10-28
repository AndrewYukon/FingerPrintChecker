import XCTest
@testable import FingerPrintChecker

private final class FakeTransportV2: HTTPTransport, @unchecked Sendable {
    var identifyBody = Data(#"{"ok":true,"protocolVersion":2,"attestation":"fpa1.x","expiresIn":600,"proofStatus":"checked"}"#.utf8)
    var queuedIdentifyBodies = [Data]()
    var challengeResponse: (Data, Int)?
    var failIdentify = false
    private(set) var requests = [URLRequest]()
    private var challenges = 0

    func send(_ request: URLRequest) async throws -> (data: Data, status: Int) {
        requests.append(request)
        if request.url?.path == "/v2/challenge" {
            if let challengeResponse { return challengeResponse }
            challenges += 1
            return (Data(#"{"ok":true,"protocolVersion":2,"challenge":"v4.c\#(challenges)","expiresIn":300}"#.utf8), 200)
        }
        if failIdentify { throw URLError(.notConnectedToInternet) }
        return (queuedIdentifyBodies.isEmpty ? identifyBody : queuedIdentifyBodies.removeFirst(), 200)
    }

    var identifyRequests: [URLRequest] { requests.filter { $0.url?.path == "/v2/identify" } }
}

private struct FakeCollectorV2: SignalCollecting {
    var token: String?
    let components = [FPComponent(key: "ios.keychainId", value: "A1B2C3D4-E5F6-4711-8899-AABBCCDDEEFF")]
    func collect(useDeviceCheck: Bool) async -> CollectedSignals {
        CollectedSignals(components: components, deviceCheckToken: useDeviceCheck ? token : nil)
    }
}

final class IdentifyFlowV2Tests: XCTestCase {
    private func makeChecker(
        _ transport: FakeTransportV2, collector: FakeCollectorV2 = FakeCollectorV2(), pow: Int? = nil,
        coordinator: AppAttestCoordinator? = nil
    ) -> FingerPrintChecker {
        FingerPrintChecker(
            config: FPConfig(publishableKey: "pk_test", powDifficulty: pow),
            platform: .ios, transport: transport, collector: collector, appAttest: coordinator)
    }

    private func body(_ request: URLRequest?) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(request?.httpBody)) as? [String: Any])
    }

    func testWireFormatAndNoSigNoSealKey() async throws {
        let transport = FakeTransportV2()
        let result = await makeChecker(transport).identify(intentToken: "fpi1.a+b&c=")
        guard case .success(let success) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(success.attestation, "fpa1.x")
        XCTAssertEqual(success.proofStatus, "checked")
        XCTAssertNil(success.visitorId)
        let challenge = transport.requests[0], identify = transport.requests[1]
        XCTAssertEqual(challenge.url?.absoluteString, "https://api.fpchecker.com/v2/challenge?intent=fpi1.a%2Bb%26c%3D")
        XCTAssertEqual(challenge.value(forHTTPHeaderField: "X-Publishable-Key"), "pk_test")
        XCTAssertEqual(identify.value(forHTTPHeaderField: "X-Publishable-Key"), "pk_test")
        XCTAssertEqual(identify.httpMethod, "POST")
        let json = try body(identify)
        XCTAssertEqual(json["protocolVersion"] as? Int, 2)
        XCTAssertEqual(json["platform"] as? String, "ios")
        XCTAssertEqual(json["intentToken"] as? String, "fpi1.a+b&c=")
        XCTAssertEqual(json["challenge"] as? String, "v4.c1")
        XCTAssertEqual(json["agentVersion"] as? String, "ios-0.7.1")
        XCTAssertNil(json["sig"])
        XCTAssertNil(json["nonce"])
        XCTAssertNil(json["proof"])
        XCTAssertNil(json["pow"])
        let comps = try XCTUnwrap(json["components"] as? [[String: String]])
        XCTAssertEqual(comps.map { $0["key"] }, ["ios.keychainId"])
    }

    func testScoreDetailsAreParsedWhenPresent() async throws {
        let transport = FakeTransportV2()
        transport.identifyBody = Data(#"{"ok":true,"protocolVersion":2,"attestation":"fpa1.x","visitorId":"i4_x","trustScore":80,"identityConfidence":90,"isNew":true,"trustDeductions":["a"],"shadowDeductions":["b"],"rulesVersion":"r1"}"#.utf8)
        let result = await makeChecker(transport).identify(intentToken: "t")
        guard case .success(let s) = result else { return XCTFail("\(result)") }
        XCTAssertEqual([s.visitorId, s.rulesVersion], ["i4_x", "r1"])
        XCTAssertEqual([s.trustScore, s.identityConfidence], [80, 90])
        XCTAssertEqual(s.isNew, true)
        XCTAssertEqual(s.trustDeductions, ["a"])
        XCTAssertEqual(s.shadowDeductions, ["b"])
    }

    func testSuccessWithoutAttestationIsFailure() async {
        for bad in [
            #"{"ok":true,"protocolVersion":2}"#,
            #"{"ok":true,"protocolVersion":2,"attestation":""}"#,
            #"{"ok":true,"protocolVersion":2,"attestation":{"a":1}}"#,
            #"{"ok":true,"visitorId":"i4_x","trustScore":90}"#,
        ] {
            let transport = FakeTransportV2()
            transport.identifyBody = Data(bad.utf8)
            let result = await makeChecker(transport).identify(intentToken: "t")
            XCTAssertEqual(result, .failure(reason: "bad_response", httpStatus: 200), bad)
        }
    }

    func testServerFailureReasonIsReported() async {
        let transport = FakeTransportV2()
        transport.identifyBody = Data(#"{"ok":false,"protocolVersion":2,"reason":"bad_intent"}"#.utf8)
        let result = await makeChecker(transport).identify(intentToken: "t")
        XCTAssertEqual(result, .failure(reason: "bad_intent", httpStatus: 200))
    }

    func testBadIntentOnChallengeStopsBeforeIdentify() async {
        let transport = FakeTransportV2()
        transport.challengeResponse = (Data(#"{"ok":false,"error":"bad_intent"}"#.utf8), 400)
        let result = await makeChecker(transport).identify(intentToken: "t")
        XCTAssertEqual(result, .failure(reason: "bad_intent", httpStatus: 400))
        XCTAssertTrue(transport.identifyRequests.isEmpty)
    }

    func testEmptyIntentFailsLocally() async {
        let transport = FakeTransportV2()
        let result = await makeChecker(transport).identify(intentToken: "")
        XCTAssertEqual(result, .failure(reason: "bad_config", httpStatus: 0))
        XCTAssertTrue(transport.requests.isEmpty)
    }

    func testPowIsSolvedOverTheChallengeAndDifficultyQueried() async throws {
        let transport = FakeTransportV2()
        _ = await makeChecker(transport, pow: 8).identify(intentToken: "t")
        XCTAssertEqual(transport.requests[0].url?.query, "intent=t&difficulty=8")
        XCTAssertEqual(try body(transport.requests[1])["pow"] as? String, ProofOfWork.solve(nonce: "v4.c1", bits: 8))
    }

    func testDeviceCheckTokenSentAtTopLevel() async throws {
        let transport = FakeTransportV2()
        _ = await makeChecker(transport, collector: FakeCollectorV2(token: "dG9r")).identify(intentToken: "t")
        XCTAssertEqual(try body(transport.requests.last)["deviceCheckToken"] as? String, "dG9r")
    }

    func testNetworkErrorOnIdentify() async {
        let transport = FakeTransportV2()
        transport.failIdentify = true
        let result = await makeChecker(transport).identify(intentToken: "t")
        XCTAssertEqual(result, .failure(reason: "network", httpStatus: 0))
    }

    func testAppAttestBindsSHA256OfTheCanonicalBytes() async throws {
        let transport = FakeTransportV2()
        let service = FakeAppAttestService()
        let store = MemoryKeyStore()
        _ = await makeChecker(transport, coordinator: AppAttestCoordinator(service: service, store: store))
            .identify(intentToken: "t")
        let json = try body(transport.requests.last)
        let canonical = try CanonicalV2.bytes(
            platform: "ios", agentVersion: "ios-0.7.1", challenge: "v4.c1",
            components: FakeCollectorV2().components)
        XCTAssertEqual(service.lastClientDataHash, FPCrypto.sha256(canonical))
        XCTAssertEqual(service.lastClientDataHash?.count, 32)
        XCTAssertNotNil((json["proof"] as? [String: Any])?["attestation"])
        XCTAssertEqual(store.keyId, "key-1")
    }

    func testUnknownKeyIsRetriedOnceWithAFreshChallengeAndANewKey() async throws {
        let transport = FakeTransportV2()
        transport.queuedIdentifyBodies = [Data(#"{"ok":true,"protocolVersion":2,"attestation":"fpa1.old","proofStatus":"unknown_key"}"#.utf8)]
        let store = MemoryKeyStore()
        store.keyId = "forgotten"
        let result = await makeChecker(
            transport, coordinator: AppAttestCoordinator(service: FakeAppAttestService(), store: store))
            .identify(intentToken: "t")
        guard case .success(let success) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(success.proofStatus, "checked")
        let posts = transport.identifyRequests
        XCTAssertEqual(posts.count, 2)
        XCTAssertNotNil((try body(posts[0])["proof"] as? [String: Any])?["assertion"])
        XCTAssertNotNil((try body(posts[1])["proof"] as? [String: Any])?["attestation"])
        XCTAssertEqual(try posts.map { try body($0)["challenge"] as? String }, ["v4.c1", "v4.c2"])
        XCTAssertEqual(store.keyId, "key-1")
    }

    func testUnknownKeyIsRetriedAtMostOnce() async throws {
        let transport = FakeTransportV2()
        transport.identifyBody = Data(#"{"ok":true,"protocolVersion":2,"attestation":"fpa1.x","proofStatus":"unknown_key"}"#.utf8)
        let store = MemoryKeyStore()
        store.keyId = "forgotten"
        _ = await makeChecker(
            transport, coordinator: AppAttestCoordinator(service: FakeAppAttestService(), store: store))
            .identify(intentToken: "t")
        XCTAssertEqual(transport.identifyRequests.count, 2)
    }
}
