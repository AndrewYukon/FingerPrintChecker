import Foundation

/// Failure classes the App Attest key state machine distinguishes.
enum AppAttestFailure: Error {
    /// Apple reported `DCError.invalidKey`: the stored key can never be used again.
    case invalidKey
    case failed
}

/// Abstraction over `DCAppAttestService` so the key state machine is testable without a device.
protocol AppAttestService: Sendable {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data
}

/// Persistence for the key id. Only a key the server has confirmed as attested is ever stored.
protocol AppAttestKeyStore: Sendable {
    func attestedKeyId() -> String?
    @discardableResult func saveAttestedKeyId(_ keyId: String) -> Bool
    func clear()
}

/// The `proof` object of an identify request.
struct AppAttestProof: Equatable, Sendable {
    enum Kind: Sendable { case attestation, assertion }
    let keyId: String
    let kind: Kind
    /// Base64 attestation or assertion object.
    let payload: String

    var json: [String: Any] {
        [
            "type": "app_attest",
            "keyId": keyId,
            kind == .attestation ? "attestation" : "assertion": payload,
        ]
    }
}

/// Key lifecycle:
/// - no stored key: generate a key and attest it; the key is stored only once the server answered
///   `proofStatus == "checked"` (Apple allows `attestKey` once per key, so an attestation whose outcome
///   is unknown is never retried with the same key);
/// - stored key: send an assertion; `unknown_key` from the server or `invalidKey` from Apple drops the key
///   so the NEXT call attests a new one (never looped within one call);
/// - any other error: no proof, identify itself is never failed by App Attest.
final class AppAttestCoordinator: @unchecked Sendable {
    private let service: AppAttestService
    private let store: AppAttestKeyStore

    init(service: AppAttestService, store: AppAttestKeyStore) {
        self.service = service
        self.store = store
    }

    func makeProof(clientDataHash: Data) async -> AppAttestProof? {
        guard service.isSupported else { return nil }
        if let keyId = store.attestedKeyId() {
            do {
                let assertion = try await service.generateAssertion(keyId, clientDataHash: clientDataHash)
                return AppAttestProof(keyId: keyId, kind: .assertion, payload: assertion.base64EncodedString())
            } catch AppAttestFailure.invalidKey {
                store.clear()
                return nil
            } catch {
                return nil
            }
        }
        do {
            let keyId = try await service.generateKey()
            let attestation = try await service.attestKey(keyId, clientDataHash: clientDataHash)
            return AppAttestProof(keyId: keyId, kind: .attestation, payload: attestation.base64EncodedString())
        } catch {
            return nil
        }
    }

    /// Feed back the outcome of the request that carried `proof`. `proofStatus` is `nil` when the
    /// request failed at network level or the response had no status.
    func recordOutcome(proof: AppAttestProof, proofStatus: String?) {
        switch (proof.kind, proofStatus) {
        case (.attestation, "checked"):
            store.saveAttestedKeyId(proof.keyId)
        case (.assertion, "unknown_key"):
            if store.attestedKeyId() == proof.keyId { store.clear() }
        default:
            break
        }
    }
}
