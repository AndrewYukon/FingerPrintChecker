import Foundation
import Security

/// Minimal generic-password Keychain wrapper (device-only, never synchronised).
struct KeychainStore: Sendable {
    static let sdkService = "com.fpchecker.sdk"
    static let appAttestService = "com.fpchecker.sdk.appattest"
    private static let missingEntitlement: OSStatus = -34018

    let service: String
    let account: String

    private enum Domain { case dataProtection, legacy }

    private func baseQuery(_ domain: Domain) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
        ]
        #if os(macOS)
        if domain == .dataProtection { query[kSecUseDataProtectionKeychain as String] = true }
        #endif
        return query
    }

    /// The data-protection keychain needs a signed app with entitlements; unsigned processes
    /// (command line tools, tests) fall back to the legacy macOS keychain. iOS has a single keychain.
    private var domains: [Domain] {
        #if os(macOS)
        return [.dataProtection, .legacy]
        #else
        return [.dataProtection]
        #endif
    }

    func read() -> String? {
        for domain in domains {
            var query = baseQuery(domain)
            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            var item: CFTypeRef?
            if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
               let data = item as? Data, let value = String(data: data, encoding: .utf8) {
                return value
            }
        }
        return nil
    }

    @discardableResult
    func write(_ value: String) -> Bool {
        for domain in domains {
            let status = writeOnce(value, domain: domain)
            if status == errSecSuccess { return true }
            if status != Self.missingEntitlement { return false }
        }
        return false
    }

    private func writeOnce(_ value: String, domain: Domain) -> OSStatus {
        let data = Data(value.utf8)
        let update = SecItemUpdate(
            baseQuery(domain) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update != errSecItemNotFound { return update }
        var add = baseQuery(domain)
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(add as CFDictionary, nil)
    }

    func delete() {
        for domain in domains { SecItemDelete(baseQuery(domain) as CFDictionary) }
    }
}

/// Random per-install identifier kept in the Keychain (`<platform>.keychainId`).
enum KeychainIdentity {
    private static let account = "keychainId"

    /// Returns the stored id, creating it on first use. `nil` when it cannot be persisted: an id that
    /// would change on every call must not be sent.
    static func load() -> String? {
        let store = KeychainStore(service: KeychainStore.sdkService, account: account)
        if let existing = ComponentRules.normalizeUUID(store.read()) { return existing }
        let fresh = UUID().uuidString
        return store.write(fresh) ? fresh : nil
    }
}

struct KeychainAppAttestKeyStore: AppAttestKeyStore {
    private let store = KeychainStore(service: KeychainStore.appAttestService, account: "keyId")

    func attestedKeyId() -> String? { store.read().flatMap { $0.isEmpty ? nil : $0 } }
    func saveAttestedKeyId(_ keyId: String) -> Bool { store.write(keyId) }
    func clear() { store.delete() }
}
