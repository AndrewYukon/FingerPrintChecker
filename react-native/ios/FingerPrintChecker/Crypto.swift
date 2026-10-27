import CryptoKit
import Foundation

/// Hashing helpers shared by the seal, proof-of-work and proof binding code.
enum FPCrypto {
    static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

    static func sha256(utf8 string: String) -> Data { sha256(Data(string.utf8)) }

    static func hex<S: Sequence>(_ data: S) -> String where S.Element == UInt8 {
        let digits = Array("0123456789abcdef")
        var out = [Character]()
        for byte in data {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0f)])
        }
        return String(out)
    }

    static func hmacSHA256Hex(key: String, message: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(message.utf8), using: SymmetricKey(data: Data(key.utf8)))
        return hex(mac)
    }
}
