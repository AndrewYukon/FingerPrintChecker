import XCTest
@testable import FingerPrintChecker

private final class FakeTransport: HTTPTransport, @unchecked Sendable {
    var identifyBody = Data(#"{"ok":true,"visitorId":"i4_x","trustScore":55,"proofStatus":"checked","attestation":"a"}"#.utf8)
    /// Answers for the next identify calls, in order; `identifyBody` once they run out.
    var queuedIdentifyBodies = [Data]()
    var failIdentify = false
    private(set) var requests = [URLRequest]()
    private var challenges = 0

    func send(_ request: URLRequest) async throws -> (data: Data, status: Int) {
        requests.append(request)
        if request.url?.path == "/v1/challenge" {
            challenges += 1
            return (Data(#"{"nonce":"nonce-\#(challenges)","expiresIn":300}"#.utf8), 200)
        }
        if failIdentify { throw URLError(.notConnectedToInternet) }
        return (queuedIdentifyBodies.isEmpty ? identifyBody : queuedIdentifyBodies.removeFirst(), 200)
    }

    var identifyRequests: [URLRequest] { requests.filter { $0.url?.path == "/v1/identify" } }
}

private struct FakeCollector: SignalCollecting {
    var components: [FPComponent] = [FPComponent(key: "ios.keychainId", value: "A1B2C3D4-E5F6-4711-8899-AABBCCDDEEFF")]
    var token: String?
    func collect(useDeviceCheck: Bool) async -> CollectedSignals {
        CollectedSignals(components: components, deviceCheckToken: useDeviceCheck ? token : nil)
    }
}

final class IdentifyFlowTests: XCTestCase {
    private func makeChecker(
        _ transport: FakeTransport, collector: FakeCollector = FakeCollector(), pow: Int? = nil,
        coordinator: AppAttestCoordinator? = nil
    ) -> FingerPrintChecker {
        FingerPrintChecker(
            config: FPConfig(publishableKey: "pk_test", sealKey: "seal", powDifficulty: pow),
            platform: .ios, transport: transport, collector: collector, appAttest: coordinator)
    }

    private func body(_ transport: FakeTransport) throws -> [String: Any] {
        let request = try XCTUnwrap(transport.requests.last)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as? [String: Any])
    }

    func testBodyIsSealedAndCarriesHeadersAndAgentVersion() async throws {
        let transport = FakeTransport()
        let result = await makeChecker(transport).identify()
        guard case .success(let success) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(success.visitorId, "i4_x")
        let challenge = transport.requests[0], identify = transport.requests[1]
        XCTAssertEqual(challenge.value(forHTTPHeaderField: "X-Publishable-Key"), "pk_test")
        XCTAssertEqual(identify.value(forHTTPHeaderField: "X-Publishable-Key"), "pk_test")
        XCTAssertEqual(identify.httpMethod, "POST")
        XCTAssertEqual(identify.timeoutInterval, 10)
        let json = try body(transport)
        XCTAssertEqual(json["platform"] as? String, "ios")
        XCTAssertEqual(json["agentVersion"] as? String, "ios-0.3.0")
        let comps = FakeCollector().components
        let canonical = Canonical.payload(nonce: "nonce-1", components: comps)
        XCTAssertEqual(json["sig"] as? String, Canonical.seal(sealKey: "seal", canonical: canonical))
        XCTAssertNil(json["proof"])
        XCTAssertNil(json["pow"])
    }

    func testPowIsSentAsStringAndDifficultyQueried() async throws {
        let transport = FakeTransport()
        _ = await makeChecker(transport, pow: 8).identify()
        XCTAssertEqual(transport.requests[0].url?.query, "difficulty=8")
        let json = try body(transport)
        let pow = try XCTUnwrap(json["pow"] as? String)
        XCTAssertEqual(pow, ProofOfWork.solve(nonce: "nonce-1", bits: 8))
    }

    func testDeviceCheckTokenSentAtTopLevel() async throws {
        let transport = FakeTransport()
        let collector = FakeCollector(
            components: FakeCollector().components + [FPComponent(key: "ios.deviceCheck", value: ComponentRules.deviceCheckHash(token: "dG9r"))],
            token: "dG9r")
        _ = await makeChecker(transport, collector: collector).identify()
        XCTAssertEqual(try body(transport)["deviceCheckToken"] as? String, "dG9r")
    }

    func testNetworkErrorOnIdentify() async {
        let transport = FakeTransport()
        transport.failIdentify = true
        let result = await makeChecker(transport).identify()
        XCTAssertEqual(result, .failure(reason: "network", httpStatus: 0))
    }

    func testNoIdentityKeyFailsLocallyWithoutPosting() async {
        let transport = FakeTransport()
        let result = await makeChecker(transport, collector: FakeCollector(components: [])).identify()
        XCTAssertEqual(result, .failure(reason: "no_device_id", httpStatus: 0))
        XCTAssertEqual(transport.requests.count, 1)
    }

    func testBadPowDifficultyIsRejected() async {
        let result = await makeChecker(FakeTransport(), pow: 3).identify()
        XCTAssertEqual(result, .failure(reason: "bad_config", httpStatus: 0))
    }

    func testAppAttestAttestThenAssertAcrossCalls() async throws {
        let transport = FakeTransport()
        let service = FakeAppAttestService()
        let store = MemoryKeyStore()
        let checker = makeChecker(transport, coordinator: AppAttestCoordinator(service: service, store: store))
        _ = await checker.identify()
        let first = try XCTUnwrap(body(transport)["proof"] as? [String: Any])
        XCTAssertNotNil(first["attestation"])
        XCTAssertEqual(first["keyId"] as? String, "key-1")
        XCTAssertEqual(store.keyId, "key-1")
        _ = await checker.identify()
        let second = try XCTUnwrap(body(transport)["proof"] as? [String: Any])
        XCTAssertNotNil(second["assertion"])
        XCTAssertNil(second["attestation"])
    }

    func testAttestationNetworkFailureDoesNotStoreKey() async throws {
        let transport = FakeTransport()
        transport.failIdentify = true
        let store = MemoryKeyStore()
        let checker = makeChecker(
            transport, coordinator: AppAttestCoordinator(service: FakeAppAttestService(), store: store))
        let result = await checker.identify()
        XCTAssertEqual(result, .failure(reason: "network", httpStatus: 0))
        XCTAssertNil(store.keyId)
    }

    func testAppAttestFailureNeverFailsIdentify() async throws {
        let transport = FakeTransport()
        let service = FakeAppAttestService()
        service.generateKeyResult = .failure(AppAttestFailure.failed)
        let result = await makeChecker(
            transport, coordinator: AppAttestCoordinator(service: service, store: MemoryKeyStore())).identify()
        guard case .success = result else { return XCTFail("\(result)") }
        XCTAssertNil(try body(transport)["proof"])
    }

    private static func answer(proofStatus: String, trust: Int) -> Data {
        Data(#"{"ok":true,"visitorId":"i4_x","trustScore":\#(trust),"proofStatus":"\#(proofStatus)","attestation":"a"}"#.utf8)
    }

    private func proof(_ request: URLRequest) throws -> [String: Any] {
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as? [String: Any])
        return try XCTUnwrap(json["proof"] as? [String: Any])
    }

    func testUnknownKeyIsRetriedOnceInTheSameCallWithAFreshNonceAndANewKey() async throws {
        let transport = FakeTransport()
        transport.queuedIdentifyBodies = [Self.answer(proofStatus: "unknown_key", trust: 45)]
        transport.identifyBody = Self.answer(proofStatus: "checked", trust: 90)
        let service = FakeAppAttestService()
        let store = MemoryKeyStore()
        store.keyId = "forgotten"
        let result = await makeChecker(transport, coordinator: AppAttestCoordinator(service: service, store: store)).identify()

        guard case .success(let success) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(success.trustScore, 90, "the caller sees the retried, attested result")
        XCTAssertEqual(success.proofStatus, "checked")
        let posts = transport.identifyRequests
        XCTAssertEqual(posts.count, 2)
        XCTAssertNotNil(try proof(posts[0])["assertion"])
        XCTAssertEqual(try proof(posts[1])["keyId"] as? String, "key-1")
        XCTAssertNotNil(try proof(posts[1])["attestation"])
        let nonces = try posts.map { try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap($0.httpBody)) as? [String: Any])["nonce"] as? String }
        XCTAssertEqual(nonces, ["nonce-1", "nonce-2"], "a nonce is single-use")
        XCTAssertEqual(store.keyId, "key-1")
    }

    func testUnknownKeyIsRetriedAtMostOnce() async throws {
        let transport = FakeTransport()
        transport.identifyBody = Self.answer(proofStatus: "unknown_key", trust: 45)
        let store = MemoryKeyStore()
        store.keyId = "forgotten"
        let result = await makeChecker(
            transport, coordinator: AppAttestCoordinator(service: FakeAppAttestService(), store: store)).identify()
        guard case .success(let success) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(success.proofStatus, "unknown_key")
        XCTAssertEqual(transport.identifyRequests.count, 2)
    }

    func testNoRetryWhenTheProofWasNotAnAssertion() async throws {
        let transport = FakeTransport()
        transport.identifyBody = Self.answer(proofStatus: "unknown_key", trust: 45)
        _ = await makeChecker(
            transport, coordinator: AppAttestCoordinator(service: FakeAppAttestService(), store: MemoryKeyStore())).identify()
        XCTAssertEqual(transport.identifyRequests.count, 1, "an attestation cannot be unknown; nothing to retry")
    }

    // MARK: v1 without a seal key

    func testV1WithoutSealKeyFailsClearlyWithoutRequests() async {
        let transport = FakeTransport()
        let checker = FingerPrintChecker(
            config: FPConfig(publishableKey: "pk_test"), platform: .ios, transport: transport,
            collector: FakeCollector(), appAttest: nil)
        let result = await checker.identify()
        XCTAssertEqual(result, .failure(reason: "seal_key_missing", httpStatus: 0))
        XCTAssertTrue(transport.requests.isEmpty)
    }
}
