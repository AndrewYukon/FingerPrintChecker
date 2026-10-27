import Foundation

/// One `key=value` pair of the sealed payload.
public struct FPComponent: Sendable, Equatable {
    public let key: String
    public let value: String

    public init(key: String, value: String) {
        self.key = key
        self.value = value
    }
}

/// Canonical payload, seal and the App Attest client data hash.
enum Canonical {
    /// `nonce + "|" + part` for every `key=value` part in plain UTF-16 code unit order,
    /// identical to JavaScript's default `Array.prototype.sort()`.
    static func payload(nonce: String, components: [FPComponent]) -> String {
        let parts = components.map { "\($0.key)=\($0.value)" }
            .sorted { Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16)) }
        return parts.reduce(nonce) { $0 + "|" + $1 }
    }

    /// Lowercase hex HMAC-SHA256 keyed with the UTF-8 bytes of the seal key.
    static func seal(sealKey: String, canonical: String) -> String {
        FPCrypto.hmacSHA256Hex(key: sealKey, message: canonical)
    }

    /// 32-byte `clientDataHash` for App Attest (and the Play Integrity `requestHash` bytes).
    static func clientDataHash(canonical: String) -> Data {
        FPCrypto.sha256(utf8: canonical)
    }
}

/// Proof of work: the smallest counter `c` with `SHA-256(nonce + ":" + c)` having `bits` leading zero bits.
enum ProofOfWork {
    static let validBits = 8...28

    static func solve(nonce: String, bits: Int) -> String? {
        guard validBits.contains(bits) else { return nil }
        let prefix = Data((nonce + ":").utf8)
        var counter: UInt64 = 0
        let limit: UInt64 = 1 << 34
        while counter < limit {
            var message = prefix
            message.append(contentsOf: Array(String(counter).utf8))
            if leadingZeroBits(FPCrypto.sha256(message)) >= bits { return String(counter) }
            counter += 1
        }
        return nil
    }

    static func leadingZeroBits(_ digest: Data) -> Int {
        var count = 0
        for byte in digest {
            if byte == 0 { count += 8; continue }
            count += byte.leadingZeroBitCount
            break
        }
        return count
    }
}
