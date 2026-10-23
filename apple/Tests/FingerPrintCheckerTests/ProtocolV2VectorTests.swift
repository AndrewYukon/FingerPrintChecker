import XCTest
@testable import FingerPrintChecker

/// Loads test-vectors/protocol-v2.json by walking up from this file.
private struct VectorsV2 {
    struct Input {
        let platform: String
        let agentVersion: String
        let challenge: String
        let components: [FPComponent]
    }
    struct Accept {
        let name: String
        let input: Input
        let canonical: String
        /// Web-only (`hash` members); native requests never carry one, so the Swift serializer has no field for it.
        let usesHash: Bool
        let requestBindingHex: String
        let clientDataHashBase64: String
    }

    let domain: String
    let accept: [Accept]
    let reject: [(name: String, input: Input)]

    static func load(file: StaticString = #filePath) throws -> VectorsV2 {
        var dir = URL(fileURLWithPath: "\(file)").deletingLastPathComponent()
        for _ in 0..<6 {
            let candidate = dir.appendingPathComponent("test-vectors/protocol-v2.json")
            if FileManager.default.fileExists(atPath: candidate.path) {
                return try parse(replacingLoneSurrogates(Data(contentsOf: candidate)))
            }
            dir.deleteLastPathComponent()
        }
        throw XCTSkip("test-vectors/protocol-v2.json not found")
    }

    /// JSONSerialization refuses a lone `\\uD800`-style escape, which Swift cannot represent anyway:
    /// turn each one into U+FFFD so the rest of the file can be read.
    private static func replacingLoneSurrogates(_ data: Data) -> Data {
        var text = String(decoding: data, as: UTF8.self)
        let high = "\\\\u[dD][89abAB][0-9a-fA-F]{2}", low = "\\\\u[dD][c-fC-F][0-9a-fA-F]{2}"
        for pattern in ["\(high)(?!\(low))", "(?<!\(high))\(low)"] {
            let regex = try! NSRegularExpression(pattern: pattern)
            text = regex.stringByReplacingMatches(
                in: text, range: NSRange(text.startIndex..., in: text), withTemplate: "\\\\uFFFD")
        }
        return Data(text.utf8)
    }

    private static func input(_ json: [String: Any]) -> Input {
        let comps = (json["components"] as? [[String: Any]] ?? []).map {
            FPComponent(key: $0["key"] as! String, value: $0["value"] as! String)
        }
        return Input(
            platform: json["platform"] as! String, agentVersion: json["agentVersion"] as! String,
            challenge: json["challenge"] as! String, components: comps)
    }

    private static func parse(_ data: Data) throws -> VectorsV2 {
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let accept = try XCTUnwrap(root["accept"] as? [[String: Any]]).map { c -> Accept in
            let inputJSON = c["input"] as! [String: Any]
            let usesHash = (inputJSON["components"] as? [[String: Any]] ?? []).contains { $0["hash"] != nil }
            return Accept(
                name: c["name"] as! String, input: input(inputJSON),
                canonical: c["canonical"] as! String, usesHash: usesHash,
                requestBindingHex: c["requestBindingHex"] as! String,
                clientDataHashBase64: c["clientDataHashBase64"] as! String)
        }
        let reject = try XCTUnwrap(root["reject"] as? [[String: Any]]).map {
            (name: $0["name"] as! String, input: input($0["input"] as! [String: Any]))
        }
        return VectorsV2(domain: root["domain"] as! String, accept: accept, reject: reject)
    }
}

final class ProtocolV2VectorTests: XCTestCase {
    func testAcceptCasesMatchCanonicalBindingAndClientDataHash() throws {
        let vectors = try VectorsV2.load()
        XCTAssertEqual(vectors.domain, CanonicalV2.domain)
        XCTAssertFalse(vectors.accept.isEmpty)
        for c in vectors.accept where !c.usesHash {
            let bytes = try CanonicalV2.bytes(
                platform: c.input.platform, agentVersion: c.input.agentVersion,
                challenge: c.input.challenge, components: c.input.components)
            XCTAssertEqual(String(decoding: bytes, as: UTF8.self), c.canonical, c.name)
            let binding = CanonicalV2.requestBinding(bytes)
            XCTAssertEqual(FPCrypto.hex(binding), c.requestBindingHex, c.name)
            XCTAssertEqual(binding.base64EncodedString(), c.clientDataHashBase64, c.name)
            XCTAssertEqual(binding.count, 32, c.name)
        }
    }

    func testRejectCasesAreRefused() throws {
        let vectors = try VectorsV2.load()
        XCTAssertFalse(vectors.reject.isEmpty)
        for r in vectors.reject {
            // A lone surrogate cannot be represented in a Swift String (the JSON parser turns it into
            // U+FFFD), so those two cases are refused by construction and can only be checked for no crash.
            let outcome = Result {
                try CanonicalV2.bytes(
                    platform: r.input.platform, agentVersion: r.input.agentVersion,
                    challenge: r.input.challenge, components: r.input.components)
            }
            if !r.name.contains("surrogate") { XCTAssertThrowsError(try outcome.get(), r.name) }
        }
    }

    func testEscapingMatchesJSONStringify() {
        XCTAssertEqual(CanonicalV2.quote("a/b<>&\u{7F}\u{2028}\u{1F600}"), "\"a/b<>&\u{7F}\u{2028}\u{1F600}\"")
        XCTAssertEqual(CanonicalV2.quote("\"\\\u{08}\u{0C}\n\r\t\u{01}\u{1F}"), #""\"\\\b\f\n\r\t\u0001\u001f""#)
    }

    func testKeyAndAgentVersionRules() {
        XCTAssertTrue(CanonicalV2.isValidKey("ios.keychainId"))
        XCTAssertFalse(CanonicalV2.isValidKey("a b"))
        XCTAssertFalse(CanonicalV2.isValidKey("é"))
        XCTAssertThrowsError(try CanonicalV2.bytes(
            platform: "ios", agentVersion: String(repeating: "v", count: 65), challenge: "c", components: []))
    }
}
