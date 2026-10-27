import Foundation

/// Why a config map was rejected; always surfaces as `bad_config`.
struct BridgeConfigError: Error {
  let message: String
}

/// Narrow seam over ``FingerPrintChecker`` so tests can force failures.
protocol Identifying: Sendable {
  func identify(intentToken: String, linkedId: String?, tags: [String: Any]?) async throws -> FPResultV2
}

/// Adapts the native checker (which never throws) to ``Identifying``.
struct NativeIdentifier: Identifying {
  let checker: FingerPrintChecker
  func identify(intentToken: String, linkedId: String?, tags: [String: Any]?) async throws -> FPResultV2 {
    await checker.identify(intentToken: intentToken, linkedId: linkedId, tags: tags)
  }
}

/// Pure bridge logic on `[String: Any]` so unit tests need no React Native runtime.
enum Bridge {
  private static let loopbackHosts: Set<String> = ["localhost", "127.0.0.1", "::1"]

  static func failure(_ reason: String, _ status: Int) -> [String: Any] {
    ["ok": false, "reason": reason, "httpStatus": status]
  }

  static func reply(_ result: FPResultV2) -> [String: Any] {
    switch result {
    case .failure(let reason, let httpStatus):
      return failure(reason, httpStatus)
    case .success(let s):
      guard !s.attestation.isEmpty else { return failure("bridge_error", 0) }
      var out: [String: Any] = [
        "ok": true,
        "visitorId": s.visitorId.map { $0 as Any } ?? NSNull(),
        "attestation": s.attestation,
        "trustDeductions": s.trustDeductions ?? [],
        "shadowDeductions": s.shadowDeductions ?? [],
        "rawJson": String(data: s.raw, encoding: .utf8) ?? "",
      ]
      if let v = s.eventId { out["eventId"] = v }
      if let v = s.trustScore { out["trustScore"] = v }
      if let v = s.identityConfidence { out["identityConfidence"] = v }
      if let v = s.isNew { out["isNew"] = v }
      if let v = s.proofStatus { out["proofStatus"] = v }
      if let v = s.expiresIn { out["expiresIn"] = v }
      if let v = s.rulesVersion { out["rulesVersion"] = v }
      if let v = s.sealedResult { out["sealedResult"] = v }
      return out
    }
  }

  static func isBool(_ value: Any?) -> Bool {
    guard let n = value as? NSNumber else { return false }
    return CFGetTypeID(n) == CFBooleanGetTypeID()
  }

  private static func wholeNumber(_ value: Any?, _ field: String) throws -> Int? {
    guard let value, !(value is NSNull) else { return nil }
    guard let n = value as? NSNumber, !isBool(n) else { throw BridgeConfigError(message: "\(field) must be a number") }
    let d = n.doubleValue
    guard d.isFinite, d == d.rounded(), abs(d) < 9e15 else {
      throw BridgeConfigError(message: "\(field) must be a whole number")
    }
    return n.intValue
  }

  private static func flag(_ value: Any?, _ field: String, default def: Bool) throws -> Bool {
    guard let value, !(value is NSNull) else { return def }
    guard isBool(value), let n = value as? NSNumber else { throw BridgeConfigError(message: "\(field) must be a boolean") }
    return n.boolValue
  }

  /// Validates the iOS-relevant fields. Android-only and unknown keys (and `sealKey`) are ignored.
  static func config(from map: [String: Any]) throws -> FPConfig {
    guard let pk = map["publishableKey"] as? String,
      !pk.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    else { throw BridgeConfigError(message: "publishableKey is required") }

    var baseURL = FPConfig.defaultBaseURL
    if let raw = map["baseUrl"], !(raw is NSNull) {
      guard let text = raw as? String, let url = URL(string: text), let scheme = url.scheme?.lowercased(),
        let host = url.host?.lowercased(), !host.isEmpty
      else { throw BridgeConfigError(message: "baseUrl is not a valid URL") }
      switch scheme {
      case "https": break
      case "http":
        guard loopbackHosts.contains(host) else {
          throw BridgeConfigError(message: "http baseUrl is only allowed on loopback")
        }
      default: throw BridgeConfigError(message: "baseUrl must be https")
      }
      baseURL = url
    }

    return FPConfig(
      baseURL: baseURL,
      publishableKey: pk,
      powDifficulty: try wholeNumber(map["powDifficulty"], "powDifficulty"),
      useAppAttest: try flag(map["useAppAttest"], "useAppAttest", default: true),
      useDeviceCheck: try flag(map["useDeviceCheck"], "useDeviceCheck", default: true),
      integrityProbes: try flag(map["integrityProbes"], "integrityProbes", default: true))
  }

  /// Canonical key of the parsed iOS-relevant fields; Android-only or unknown keys never matter.
  static func instanceKey(_ c: FPConfig) -> String {
    [
      c.baseURL.absoluteString, c.publishableKey, c.powDifficulty.map(String.init) ?? "-",
      String(c.useAppAttest), String(c.useDeviceCheck), String(c.integrityProbes),
    ].joined(separator: "|")
  }

  /// Channel values (NSNumber/String/NSNull/Array/Dictionary) pass through unchanged, so bool, int and double
  /// stay distinct NSNumbers; only dictionary keys are forced to strings.
  static func normalizeTags(_ value: Any?) -> [String: Any]? {
    guard let dict = value as? [AnyHashable: Any] else { return nil }
    return normalizeDict(dict)
  }

  private static func normalizeDict(_ dict: [AnyHashable: Any]) -> [String: Any] {
    var out: [String: Any] = [:]
    for (k, v) in dict { out["\(k.base)"] = normalizeValue(v) }
    return out
  }

  private static func normalizeValue(_ v: Any) -> Any {
    if let d = v as? [AnyHashable: Any] { return normalizeDict(d) }
    if let a = v as? [Any] { return a.map(normalizeValue) }
    return v
  }
}

/// Owns one ``Identifying`` per distinct config, guarded by a serial queue, and turns every outcome into a
/// reply map. ``handle(_:)`` never throws.
final class IdentifyHandler: @unchecked Sendable {
  private let factory: (FPConfig) -> Identifying
  private let queue = DispatchQueue(label: "com.fpchecker.reactnative.instances")
  private var instances: [String: Identifying] = [:]

  init(factory: @escaping (FPConfig) -> Identifying) { self.factory = factory }

  private func instance(for config: FPConfig) -> Identifying {
    queue.sync {
      let key = Bridge.instanceKey(config)
      if let existing = instances[key] { return existing }
      let created = factory(config)
      instances[key] = created
      return created
    }
  }

  func handle(_ arguments: Any?) async -> [String: Any] {
    guard let args = arguments as? [String: Any] else { return Bridge.failure("bridge_error", 0) }
    guard let configMap = args["config"] as? [String: Any], let config = try? Bridge.config(from: configMap) else {
      return Bridge.failure("bad_config", 0)
    }
    guard let token = args["intentToken"] as? String, !token.isEmpty else {
      return Bridge.failure("bad_intent_token", 0)
    }
    let linkedId = args["linkedId"] as? String
    let tags = Bridge.normalizeTags(args["tags"])
    do {
      let result = try await instance(for: config).identify(intentToken: token, linkedId: linkedId, tags: tags)
      return Bridge.reply(result)
    } catch {
      return Bridge.failure("bridge_error", 0)
    }
  }

  func close() { queue.sync { instances.removeAll() } }
}

/// Delivers a value at most once.
final class ReplyOnce: @unchecked Sendable {
  private let lock = NSLock()
  private var done = false
  private let deliver: (Any) -> Void

  init(_ deliver: @escaping (Any) -> Void) { self.deliver = deliver }

  func resolve(_ value: Any) {
    lock.lock()
    let first = !done
    done = true
    lock.unlock()
    if first { deliver(value) }
  }
}

/// Tracks in-flight calls. `finish` may run before `register` (a fast task); neither order leaves an entry.
final class InflightTracker: @unchecked Sendable {
  private let lock = NSLock()
  private var entries: [UUID: (task: Task<Void, Never>, once: ReplyOnce)] = [:]
  private var finishedEarly: Set<UUID> = []
  private var closed = false

  var count: Int { lock.lock(); defer { lock.unlock() }; return entries.count }

  /// False when the call already finished or the tracker is closed; the caller must then not expect tracking.
  func register(_ id: UUID, task: Task<Void, Never>, once: ReplyOnce) -> Bool {
    lock.lock(); defer { lock.unlock() }
    if finishedEarly.remove(id) != nil { return false }
    if closed { return false }
    entries[id] = (task, once)
    return true
  }

  func finish(_ id: UUID) {
    lock.lock(); defer { lock.unlock() }
    if entries.removeValue(forKey: id) == nil && !closed { finishedEarly.insert(id) }
  }

  /// Closes the tracker and returns everything still pending.
  func drain() -> [(task: Task<Void, Never>, once: ReplyOnce)] {
    lock.lock(); defer { lock.unlock() }
    closed = true
    let all = Array(entries.values)
    entries = [:]
    finishedEarly = []
    return all
  }
}
