import XCTest
@testable import FingerPrintChecker

final class ProtocolVectorTests: XCTestCase {
    func testAppleCasesMatchCanonicalSigAndClientDataHash() throws {
        let vectors = try Vectors.load()
        let apple = vectors.cases.filter { $0.platform == "ios" || $0.platform == "macos" }
        XCTAssertEqual(apple.count, 2)
        for c in apple {
            let components = c.components.map { FPComponent(key: $0.key, value: $0.value) }
            let canonical = Canonical.payload(nonce: vectors.nonce, components: components)
            XCTAssertEqual(canonical, c.canonical, c.name)
            XCTAssertEqual(Canonical.seal(sealKey: vectors.sealKey, canonical: canonical), c.sig, c.name)
            XCTAssertEqual(
                Canonical.clientDataHash(canonical: canonical).base64EncodedString(), c.clientDataHashBase64, c.name)
            XCTAssertEqual(Canonical.clientDataHash(canonical: canonical).count, 32)
        }
    }

    func testComponentOrderDoesNotMatter() throws {
        let vectors = try Vectors.load()
        let c = try XCTUnwrap(vectors.cases.first { $0.platform == "ios" })
        let components = c.components.map { FPComponent(key: $0.key, value: $0.value) }
        XCTAssertEqual(
            Canonical.payload(nonce: vectors.nonce, components: components.reversed()), c.canonical)
    }

    func testSortsJoinedKeyValueStringsNotKeys() {
        // Sorting by key would put "a" first; the server sorts "key=value" strings, and '.' < '='.
        let components = [FPComponent(key: "a", value: "z"), FPComponent(key: "a.b", value: "y")]
        XCTAssertEqual(Canonical.payload(nonce: "n", components: components), "n|a.b=y|a=z")
        XCTAssertEqual(Canonical.payload(nonce: "n", components: components.reversed()), "n|a.b=y|a=z")
    }

    func testSortUsesUTF16CodeUnitOrder() {
        // U+FF5E (BMP) vs U+1F600 (surrogate pair D83D...): UTF-16 order puts the emoji first.
        let components = [FPComponent(key: "k", value: "\u{FF5E}"), FPComponent(key: "k", value: "\u{1F600}")]
        XCTAssertEqual(Canonical.payload(nonce: "n", components: components), "n|k=\u{1F600}|k=\u{FF5E}")
    }

    func testProofOfWorkVector() throws {
        let vectors = try Vectors.load()
        XCTAssertEqual(ProofOfWork.solve(nonce: vectors.powNonce, bits: vectors.powBits), vectors.powSolution)
    }

    func testProofOfWorkRejectsOutOfRangeDifficulty() {
        XCTAssertNil(ProofOfWork.solve(nonce: "n", bits: 7))
        XCTAssertNil(ProofOfWork.solve(nonce: "n", bits: 29))
    }

    func testLeadingZeroBits() {
        XCTAssertEqual(ProofOfWork.leadingZeroBits(Data([0x00, 0x0f, 0xff])), 12)
        XCTAssertEqual(ProofOfWork.leadingZeroBits(Data([0x80])), 0)
        XCTAssertEqual(ProofOfWork.leadingZeroBits(Data([0x00, 0x00])), 16)
    }
}
