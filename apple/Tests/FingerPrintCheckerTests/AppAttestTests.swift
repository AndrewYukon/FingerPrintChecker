import XCTest
@testable import FingerPrintChecker

final class FakeAppAttestService: AppAttestService, @unchecked Sendable {
    var isSupported = true
    var generateKeyResult: Result<String, Error> = .success("key-1")
    var attestResult: Result<Data, Error> = .success(Data([1, 2, 3]))
    var assertionResult: Result<Data, Error> = .success(Data([9, 9]))
    private(set) var generatedKeys = 0
    private(set) var attested = [String]()
    private(set) var asserted = [String]()

    func generateKey() async throws -> String {
        generatedKeys += 1
        return try generateKeyResult.get()
    }

    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        attested.append(keyId)
        return try attestResult.get()
    }

    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        asserted.append(keyId)
        return try assertionResult.get()
    }
}

final class MemoryKeyStore: AppAttestKeyStore, @unchecked Sendable {
    var keyId: String?
    func attestedKeyId() -> String? { keyId }
    func saveAttestedKeyId(_ keyId: String) -> Bool { self.keyId = keyId; return true }
    func clear() { keyId = nil }
}

final class AppAttestTests: XCTestCase {
    private let cdHash = Data(repeating: 7, count: 32)
    private var service: FakeAppAttestService!
    private var store: MemoryKeyStore!
    private var coordinator: AppAttestCoordinator!

    override func setUp() {
        service = FakeAppAttestService()
        store = MemoryKeyStore()
        coordinator = AppAttestCoordinator(service: service, store: store)
    }

    func testFirstCallAttestsAndStoresOnlyAfterChecked() async throws {
        let proofOpt = await coordinator.makeProof(clientDataHash: cdHash)
        let proof = try XCTUnwrap(proofOpt)
        XCTAssertEqual(proof.kind, .attestation)
        XCTAssertEqual(proof.keyId, "key-1")
        XCTAssertEqual(proof.json["attestation"] as? String, Data([1, 2, 3]).base64EncodedString())
        XCTAssertEqual(proof.json["type"] as? String, "app_attest")
        XCTAssertNil(proof.json["assertion"])
        XCTAssertNil(store.keyId, "must not be stored before the server confirmed it")
        coordinator.recordOutcome(proof: proof, proofStatus: "checked")
        XCTAssertEqual(store.keyId, "key-1")
    }

    func testSubsequentCallAsserts() async throws {
        store.keyId = "key-1"
        let proofOpt = await coordinator.makeProof(clientDataHash: cdHash)
        let proof = try XCTUnwrap(proofOpt)
        XCTAssertEqual(proof.kind, .assertion)
        XCTAssertEqual(proof.json["assertion"] as? String, Data([9, 9]).base64EncodedString())
        XCTAssertNil(proof.json["attestation"])
        XCTAssertEqual(service.generatedKeys, 0)
        coordinator.recordOutcome(proof: proof, proofStatus: "checked")
        XCTAssertEqual(store.keyId, "key-1")
    }

    func testUnknownKeyResetsSoNextCallAttestsNewKey() async throws {
        store.keyId = "old"
        let proofOpt = await coordinator.makeProof(clientDataHash: cdHash)
        let proof = try XCTUnwrap(proofOpt)
        coordinator.recordOutcome(proof: proof, proofStatus: "unknown_key")
        XCTAssertNil(store.keyId)
        service.generateKeyResult = .success("fresh")
        let nextOpt = await coordinator.makeProof(clientDataHash: cdHash)
        let next = try XCTUnwrap(nextOpt)
        XCTAssertEqual(next.kind, .attestation)
        XCTAssertEqual(next.keyId, "fresh")
    }

    func testNetworkFailureDuringAttestationForcesNewKeyNextTime() async throws {
        let firstOpt = await coordinator.makeProof(clientDataHash: cdHash)
        let first = try XCTUnwrap(firstOpt)
        coordinator.recordOutcome(proof: first, proofStatus: nil)
        XCTAssertNil(store.keyId)
        service.generateKeyResult = .success("key-2")
        let secondOpt = await coordinator.makeProof(clientDataHash: cdHash)
        let second = try XCTUnwrap(secondOpt)
        XCTAssertEqual(second.kind, .attestation)
        XCTAssertEqual(second.keyId, "key-2")
        XCTAssertEqual(service.attested, ["key-1", "key-2"])
    }

    func testNonCheckedAttestationStatusIsNotStored() async throws {
        let proofOpt = await coordinator.makeProof(clientDataHash: cdHash)
        let proof = try XCTUnwrap(proofOpt)
        coordinator.recordOutcome(proof: proof, proofStatus: "unconfigured")
        XCTAssertNil(store.keyId)
    }

    func testInvalidKeyOnAssertionDropsKeyWithoutLooping() async {
        store.keyId = "old"
        service.assertionResult = .failure(AppAttestFailure.invalidKey)
        let proof = await coordinator.makeProof(clientDataHash: cdHash)
        XCTAssertNil(proof)
        XCTAssertNil(store.keyId)
        XCTAssertEqual(service.generatedKeys, 0, "no new key within the same call")
    }

    func testOtherAssertionErrorKeepsKeyAndSendsNoProof() async {
        store.keyId = "k"
        service.assertionResult = .failure(AppAttestFailure.failed)
        let proof = await coordinator.makeProof(clientDataHash: cdHash)
        XCTAssertNil(proof)
        XCTAssertEqual(store.keyId, "k")
    }

    func testErrorsYieldNoProof() async {
        service.generateKeyResult = .failure(AppAttestFailure.failed)
        let a = await coordinator.makeProof(clientDataHash: cdHash)
        XCTAssertNil(a)
        service.generateKeyResult = .success("k")
        service.attestResult = .failure(AppAttestFailure.invalidKey)
        let b = await coordinator.makeProof(clientDataHash: cdHash)
        XCTAssertNil(b)
        XCTAssertNil(store.keyId)
    }

    func testUnsupportedDeviceSendsNoProofAndTouchesNothing() async {
        service.isSupported = false
        let proof = await coordinator.makeProof(clientDataHash: cdHash)
        XCTAssertNil(proof)
        XCTAssertEqual(service.generatedKeys, 0)
    }
}
