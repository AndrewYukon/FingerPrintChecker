import Foundation
import XCTest

/// Loads test-vectors/protocol-v1.json by walking up from this file.
struct Vectors {
    struct Case {
        let name: String
        let platform: String
        let components: [(key: String, value: String)]
        let canonical: String
        let sig: String
        let clientDataHashBase64: String
    }

    let sealKey: String
    let nonce: String
    let cases: [Case]
    let powNonce: String
    let powBits: Int
    let powSolution: String

    static func load(file: StaticString = #filePath) throws -> Vectors {
        var dir = URL(fileURLWithPath: "\(file)").deletingLastPathComponent()
        for _ in 0..<6 {
            let candidate = dir.appendingPathComponent("test-vectors/protocol-v1.json")
            if FileManager.default.fileExists(atPath: candidate.path) {
                return try parse(Data(contentsOf: candidate))
            }
            dir.deleteLastPathComponent()
        }
        throw XCTSkip("test-vectors/protocol-v1.json not found")
    }

    private static func parse(_ data: Data) throws -> Vectors {
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let cases = try XCTUnwrap(root["cases"] as? [[String: Any]]).map { c -> Case in
            let comps = (c["components"] as? [[String: String]] ?? []).map { (key: $0["key"]!, value: $0["value"]!) }
            return Case(
                name: c["name"] as! String, platform: c["platform"] as! String, components: comps,
                canonical: c["canonical"] as! String, sig: c["sig"] as! String,
                clientDataHashBase64: c["clientDataHashBase64"] as! String)
        }
        let pow = try XCTUnwrap(root["pow"] as? [String: Any])
        return Vectors(
            sealKey: root["sealKey"] as! String, nonce: root["nonce"] as! String, cases: cases,
            powNonce: pow["nonce"] as! String, powBits: pow["bits"] as! Int, powSolution: pow["solution"] as! String)
    }
}
