import Foundation

/// Why a v2 request cannot be built; the server would answer `bad_request` for each of these.
enum CanonicalV2Error: Error, Equatable {
    case duplicateKey(String)
    case badKey(String)
    case agentVersionTooLong
}

/// Canonical bytes of the v2 identify request: UTF-8 of the RFC 8785 (JCS) form of
/// `{agentVersion, challenge, components, domain, platform, protocolVersion}`.
/// Written by hand because platform JSON encoders differ in how they escape `/`, `<` or U+2028.
/// Swift strings cannot hold a lone surrogate, so that server rule cannot be violated here.
enum CanonicalV2 {
    static let domain = "fpchecker.identify.v2"
    static let maxKeyLength = 64
    static let maxAgentVersion = 64

    static func bytes(
        platform: String, agentVersion: String, challenge: String, components: [FPComponent]
    ) throws -> Data {
        guard agentVersion.utf16.count <= maxAgentVersion else { throw CanonicalV2Error.agentVersionTooLong }
        var seen = Set<String>()
        for component in components {
            guard isValidKey(component.key) else { throw CanonicalV2Error.badKey(component.key) }
            guard seen.insert(component.key).inserted else { throw CanonicalV2Error.duplicateKey(component.key) }
        }
        let sorted = components.sorted { Array($0.key.utf16).lexicographicallyPrecedes(Array($1.key.utf16)) }
        let items = sorted.map { "{\"key\":\(quote($0.key)),\"value\":\(quote($0.value))}" }
        let text = "{\"agentVersion\":\(quote(agentVersion)),\"challenge\":\(quote(challenge)),"
            + "\"components\":[\(items.joined(separator: ","))],\"domain\":\(quote(domain)),"
            + "\"platform\":\(quote(platform)),\"protocolVersion\":2}"
        return Data(text.utf8)
    }

    /// SHA-256 of the canonical bytes: the App Attest `clientDataHash` (32 raw bytes).
    static func requestBinding(_ bytes: Data) -> Data { FPCrypto.sha256(bytes) }

    /// `^[A-Za-z0-9._-]{1,64}$`
    static func isValidKey(_ key: String) -> Bool {
        let units = key.utf8
        guard (1...maxKeyLength).contains(units.count) else { return false }
        return units.allSatisfy { byte in
            (0x30...0x39).contains(byte) || (0x41...0x5a).contains(byte) || (0x61...0x7a).contains(byte)
                || byte == 0x2e || byte == 0x5f || byte == 0x2d
        }
    }

    /// A string as ECMAScript `JSON.stringify` writes it.
    static func quote(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case _ where scalar.value < 0x20:
                out += "\\u00" + FPCrypto.hex([UInt8(scalar.value)])
            default: out.unicodeScalars.append(scalar)
            }
        }
        return out + "\""
    }
}
