import Foundation

/// Encodes the `<platform>.integrity` component: `<version>:<fired csv>:<unavailable csv>`, codes in
/// ``codes(for:)`` order.
enum IntegrityProbes {
    static let version = 1
    /// Total budget for one collection.
    static let defaultTimeout: TimeInterval = 0.3

    static func codes(for platform: FPPlatform) -> [String] {
        switch platform {
        case .ios: return ["jailbreak", "hook", "emulator", "debugger", "mitm", "vpn", "mock_location"]
        case .macos: return ["debugger", "hook"]
        }
    }

    /// A code missing from `results` is reported unavailable, never clean. Codes the platform does not
    /// have are dropped.
    static func encode(_ results: [String: ProbeResult], platform: FPPlatform) -> String {
        let codes = codes(for: platform)
        let fired = codes.filter { results[$0] == .fired }
        let unavailable = codes.filter { (results[$0] ?? .unavailable) == .unavailable }
        return "\(version):\(fired.joined(separator: ",")):\(unavailable.joined(separator: ","))"
    }

    /// What the SDK sends when probes are switched off: every code unavailable, nothing fired.
    static func disabled(platform: FPPlatform) -> String {
        encode([:], platform: platform)
    }

    static func collect(
        env: ProbeEnvironment, platform: FPPlatform, timeout: TimeInterval = defaultTimeout
    ) async -> String {
        let wanted = Set(codes(for: platform))
        return await collect(env: env, platform: platform, probes: allProbes.filter { wanted.contains($0.code) }, timeout: timeout)
    }

    /// Probes run in parallel on a concurrent queue and share one deadline. We wait once for all of them and
    /// then read whatever finished: a probe that threw, or had not finished at the deadline, is unavailable,
    /// and a slow probe never costs the results of the others. A blocked probe is abandoned, not joined.
    static func collect(
        env: ProbeEnvironment, platform: FPPlatform, probes: [Probe], timeout: TimeInterval
    ) async -> String {
        let board = ResultBoard()
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "fpchecker.integrity", qos: .userInitiated, attributes: .concurrent)
        for probe in probes {
            group.enter()
            queue.async {
                board.record(probe.code, (try? probe.run(env)) ?? .unavailable)
                group.leave()
            }
        }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let once = Once(continuation)
            group.notify(queue: queue) { once.resume() }
            queue.asyncAfter(deadline: .now() + timeout) { once.resume() }
        }
        return encode(board.snapshot(), platform: platform)
    }
}

private final class ResultBoard: @unchecked Sendable {
    private let lock = NSLock()
    private var results = [String: ProbeResult]()
    private var sealed = false

    func record(_ code: String, _ result: ProbeResult) {
        lock.lock(); defer { lock.unlock() }
        if !sealed { results[code] = result }
    }

    /// Copies the results and ignores anything that arrives later.
    func snapshot() -> [String: ProbeResult] {
        lock.lock(); defer { lock.unlock() }
        sealed = true
        return results
    }
}

private final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Never>?
    init(_ continuation: CheckedContinuation<Void, Never>) { self.continuation = continuation }

    func resume() {
        lock.lock()
        let c = continuation
        continuation = nil
        lock.unlock()
        c?.resume()
    }
}
