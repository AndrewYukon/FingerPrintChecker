import DeviceCheck
import Foundation

/// `DCAppAttestService` behind the testable protocol. Real device only.
struct SystemAppAttestService: AppAttestService {
    private var service: DCAppAttestService { DCAppAttestService.shared }

    var isSupported: Bool { service.isSupported }

    func generateKey() async throws -> String {
        try await call { try await service.generateKey() }
    }

    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await call { try await service.attestKey(keyId, clientDataHash: clientDataHash) }
    }

    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await call { try await service.generateAssertion(keyId, clientDataHash: clientDataHash) }
    }

    private func call<T>(_ operation: () async throws -> T) async throws -> T {
        do {
            return try await operation()
        } catch let error as DCError where error.code == .invalidKey {
            throw AppAttestFailure.invalidKey
        } catch {
            throw AppAttestFailure.failed
        }
    }
}
