import XCTest
@testable import fingerprintchecker

private struct Boom: Error {}

private final class FakeIdentifier: Identifying, @unchecked Sendable {
  var result: Result<FPResultV2, Error>
  private let lock = NSLock()
  private(set) var seenTags: [[String: Any]?] = []
  init(_ result: Result<FPResultV2, Error>) { self.result = result }
  func identify(intentToken: String, linkedId: String?, tags: [String: Any]?) async throws -> FPResultV2 {
    lock.lock(); seenTags.append(tags); lock.unlock()
    return try result.get()
  }
}

private func ok() -> FPResultV2 { .success(FPSuccessV2(attestation: "att", visitorId: "v", raw: Data("{}".utf8))) }

final class BridgeTests: XCTestCase {
  // MARK: reply mapping

  func testSuccessReplyMapsFields() {
    let s = FPSuccessV2(
      attestation: "att", expiresIn: 60, proofStatus: "checked", visitorId: "v1", trustScore: 80,
      identityConfidence: 90, isNew: true, trustDeductions: ["a"], shadowDeductions: ["b"],
      rulesVersion: "r1", eventId: "e1", sealedResult: "fpsr1.x", raw: Data("{\"a\":1}".utf8))
    let r = Bridge.reply(.success(s))
    XCTAssertEqual(r["ok"] as? Bool, true)
    XCTAssertEqual(r["visitorId"] as? String, "v1")
    XCTAssertEqual(r["attestation"] as? String, "att")
    XCTAssertEqual(r["eventId"] as? String, "e1")
    XCTAssertEqual(r["trustScore"] as? Int, 80)
    XCTAssertEqual(r["identityConfidence"] as? Int, 90)
    XCTAssertEqual(r["expiresIn"] as? Int, 60)
    XCTAssertEqual(r["isNew"] as? Bool, true)
    XCTAssertEqual(r["trustDeductions"] as? [String], ["a"])
    XCTAssertEqual(r["shadowDeductions"] as? [String], ["b"])
    XCTAssertEqual(r["proofStatus"] as? String, "checked")
    XCTAssertEqual(r["rulesVersion"] as? String, "r1")
    XCTAssertEqual(r["sealedResult"] as? String, "fpsr1.x")
    XCTAssertEqual(r["rawJson"] as? String, "{\"a\":1}")
  }

  func testListsDefaultToEmptyAndOptionalsAreOmitted() {
    let r = Bridge.reply(ok())
    XCTAssertEqual(r["trustDeductions"] as? [String], [])
    XCTAssertEqual(r["shadowDeductions"] as? [String], [])
    XCTAssertEqual(r["visitorId"] as? String, "v")
    XCTAssertNil(r["trustScore"])
    XCTAssertNil(r["eventId"])
    XCTAssertEqual(r["rawJson"] as? String, "{}")
  }

  func testFailureMapping() {
    let r = Bridge.reply(.failure(reason: "network", httpStatus: 503))
    XCTAssertEqual(r["ok"] as? Bool, false)
    XCTAssertEqual(r["reason"] as? String, "network")
    XCTAssertEqual(r["httpStatus"] as? Int, 503)
    let f = Bridge.failure("bridge_error", 0)
    XCTAssertEqual(f["reason"] as? String, "bridge_error")
    XCTAssertEqual(f["httpStatus"] as? Int, 0)
    XCTAssertEqual(f["ok"] as? Bool, false)
  }

  func testNonUtf8RawGivesEmptyRawJson() {
    let s = FPSuccessV2(attestation: "att", visitorId: "v", raw: Data([0xff, 0xfe, 0xfd]))
    XCTAssertEqual(Bridge.reply(.success(s))["rawJson"] as? String, "")
  }

  // MARK: config

  private func assertBadConfig(_ map: [String: Any], file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertThrowsError(try Bridge.config(from: map), file: file, line: line)
  }

  func testEmptyOrMissingPkIsBadConfig() {
    assertBadConfig(["publishableKey": ""])
    assertBadConfig(["publishableKey": "   "])
    assertBadConfig([:])
    assertBadConfig(["publishableKey": 5])
  }

  func testBaseUrlRules() throws {
    assertBadConfig(["publishableKey": "pk", "baseUrl": "http://example.com"])
    assertBadConfig(["publishableKey": "pk", "baseUrl": "ftp://example.com"])
    assertBadConfig(["publishableKey": "pk", "baseUrl": "not a url"])
    assertBadConfig(["publishableKey": "pk", "baseUrl": ""])
    assertBadConfig(["publishableKey": "pk", "baseUrl": 3])
    _ = try Bridge.config(from: ["publishableKey": "pk", "baseUrl": "https://api.example.com"])
    _ = try Bridge.config(from: ["publishableKey": "pk", "baseUrl": "http://localhost:8080"])
    _ = try Bridge.config(from: ["publishableKey": "pk", "baseUrl": "http://127.0.0.1:8080/x"])
    _ = try Bridge.config(from: ["publishableKey": "pk", "baseUrl": "http://[::1]:8080"])
  }

  func testConfigFieldsParsed() throws {
    let c = try Bridge.config(from: [
      "publishableKey": "pk", "powDifficulty": NSNumber(value: 12), "integrityProbes": false,
      "useAppAttest": false, "useDeviceCheck": false, "sealKey": "never",
    ])
    XCTAssertEqual(c.publishableKey, "pk")
    XCTAssertEqual(c.powDifficulty, 12)
    XCTAssertFalse(c.integrityProbes)
    XCTAssertFalse(c.useAppAttest)
    XCTAssertFalse(c.useDeviceCheck)
    XCTAssertNil(c.sealKey)
    XCTAssertEqual(c.baseURL, FPConfig.defaultBaseURL)
  }

  // MARK: handler

  func testBadArgsAndBadConfigReplies() async {
    let h = IdentifyHandler { _ in FakeIdentifier(.success(ok())) }
    let r1 = await h.handle("nope")
    XCTAssertEqual(r1["reason"] as? String, "bridge_error")
    let r2 = await h.handle(["config": ["publishableKey": ""], "intentToken": "t"])
    XCTAssertEqual(r2["reason"] as? String, "bad_config")
    let r3 = await h.handle(["config": ["publishableKey": "pk", "baseUrl": "http://example.com"], "intentToken": "t"])
    XCTAssertEqual(r3["reason"] as? String, "bad_config")
    let r4 = await h.handle(["intentToken": "t"])
    XCTAssertEqual(r4["reason"] as? String, "bad_config")
    let r5 = await h.handle(["config": ["publishableKey": "pk"], "intentToken": ""])
    XCTAssertEqual(r5["reason"] as? String, "bad_intent_token")
  }

  func testForcedThrowGivesBridgeError() async {
    let h = IdentifyHandler { _ in FakeIdentifier(.failure(Boom())) }
    let r = await h.handle(["config": ["publishableKey": "pk"], "intentToken": "t"])
    XCTAssertEqual(r["ok"] as? Bool, false)
    XCTAssertEqual(r["reason"] as? String, "bridge_error")
  }

  func testOneInstancePerConfigIgnoringAndroidOnlyKeys() async {
    let count = NSLock()
    var made = 0
    let h = IdentifyHandler { _ in
      count.lock(); made += 1; count.unlock()
      return FakeIdentifier(.success(ok()))
    }
    let a: [String: Any] = ["publishableKey": "pk"]
    let b: [String: Any] = ["publishableKey": "pk", "cloudProjectNumber": 42, "integrityTimeoutMillis": 9000, "mystery": "x"]
    async let r1 = h.handle(["config": a, "intentToken": "t"])
    async let r2 = h.handle(["config": b, "intentToken": "t"])
    async let r3 = h.handle(["config": a, "intentToken": "t"])
    let all = await [r1, r2, r3]
    XCTAssertTrue(all.allSatisfy { $0["ok"] as? Bool == true })
    XCTAssertEqual(made, 1)
    _ = await h.handle(["config": ["publishableKey": "pk2"], "intentToken": "t"])
    XCTAssertEqual(made, 2)
    _ = await h.handle(["config": ["publishableKey": "pk", "useAppAttest": false], "intentToken": "t"])
    XCTAssertEqual(made, 3)
  }

  func testTagsPreserveBoolIntDouble() async throws {
    let fake = FakeIdentifier(.success(ok()))
    let h = IdentifyHandler { _ in fake }
    let tags: [String: Any] = [
      "b": NSNumber(value: true), "i": NSNumber(value: 1), "d": NSNumber(value: 1.0 as Double),
      "n": NSNull(), "s": "x", "l": [NSNumber(value: false), ["k": NSNumber(value: 2.5)]],
    ]
    _ = await h.handle(["config": ["publishableKey": "pk"], "intentToken": "t", "linkedId": "u", "tags": tags])
    let seen = try XCTUnwrap(fake.seenTags.first ?? nil)
    func isBool(_ v: Any?) -> Bool { (v as? NSNumber).map { CFGetTypeID($0) == CFBooleanGetTypeID() } ?? false }
    func isFloat(_ v: Any?) -> Bool { (v as? NSNumber).map { CFNumberIsFloatType($0) } ?? false }
    XCTAssertTrue(isBool(seen["b"]))
    XCTAssertFalse(isBool(seen["i"]))
    XCTAssertFalse(isFloat(seen["i"]))
    XCTAssertTrue(isFloat(seen["d"]))
    XCTAssertTrue(seen["n"] is NSNull)
    XCTAssertEqual(seen["s"] as? String, "x")
    let list = try XCTUnwrap(seen["l"] as? [Any])
    XCTAssertTrue(isBool(list[0]))
    XCTAssertTrue(isFloat((list[1] as? [String: Any])?["k"]))
  }

  func testNormalizeTagsStringifiesKeys() {
    let out = Bridge.normalizeTags([1: "a"] as [AnyHashable: Any])
    XCTAssertEqual(out?["1"] as? String, "a")
    XCTAssertNil(Bridge.normalizeTags("str"))
    XCTAssertNil(Bridge.normalizeTags(nil))
  }

  func testReplyOnceResolvesExactlyOnce() {
    var got: [String] = []
    let once = ReplyOnce { got.append(($0 as? [String: Any])?["reason"] as? String ?? "") }
    once.resolve(Bridge.failure("a", 0))
    once.resolve(Bridge.failure("b", 0))
    XCTAssertEqual(got, ["a"])
  }

  func testSuccessWithoutVisitorIdOrAttestationIsBridgeError() {
    for s in [
      FPSuccessV2(attestation: "att", raw: Data()),
      FPSuccessV2(attestation: "att", visitorId: "", raw: Data()),
      FPSuccessV2(attestation: "", visitorId: "v", raw: Data()),
    ] {
      let r = Bridge.reply(.success(s))
      XCTAssertEqual(r["ok"] as? Bool, false)
      XCTAssertEqual(r["reason"] as? String, "bridge_error")
    }
  }

  func testBaseUrlSchemeCaseAndMissingHost() throws {
    _ = try Bridge.config(from: ["publishableKey": "pk", "baseUrl": "HTTP://localhost:8080"])
    _ = try Bridge.config(from: ["publishableKey": "pk", "baseUrl": "HTTPS://fpchecker.com"])
    assertBadConfig(["publishableKey": "pk", "baseUrl": "http://10.0.2.2"])
    assertBadConfig(["publishableKey": "pk", "baseUrl": "https://"])
    assertBadConfig(["publishableKey": "pk", "baseUrl": "ftp://x"])
  }

  func testInflightTrackerToleratesBothOrders() {
    let tracker = InflightTracker()
    let once = ReplyOnce { _ in }
    // finish before register: nothing may stay behind
    let early = UUID()
    tracker.finish(early)
    XCTAssertFalse(tracker.register(early, task: Task {}, once: once))
    XCTAssertEqual(tracker.count, 0)
    // register then finish
    let late = UUID()
    XCTAssertTrue(tracker.register(late, task: Task {}, once: once))
    XCTAssertEqual(tracker.count, 1)
    tracker.finish(late)
    XCTAssertEqual(tracker.count, 0)
    // drain closes the tracker
    let id = UUID()
    XCTAssertTrue(tracker.register(id, task: Task {}, once: once))
    XCTAssertEqual(tracker.drain().count, 1)
    XCTAssertFalse(tracker.register(UUID(), task: Task {}, once: once))
    XCTAssertEqual(tracker.count, 0)
  }
}
