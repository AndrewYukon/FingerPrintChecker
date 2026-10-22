import Foundation

/// Network access, injectable for tests.
protocol HTTPTransport: Sendable {
    func send(_ request: URLRequest) async throws -> (data: Data, status: Int)
}

struct URLSessionTransport: HTTPTransport {
    private let session: URLSession

    init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = FingerPrintChecker.requestTimeout
        configuration.timeoutIntervalForResource = FingerPrintChecker.requestTimeout
        configuration.waitsForConnectivity = false
        session = URLSession(configuration: configuration)
    }

    func send(_ request: URLRequest) async throws -> (data: Data, status: Int) {
        let (data, response) = try await session.data(for: request)
        return (data, (response as? HTTPURLResponse)?.statusCode ?? 0)
    }
}

private enum NonceOutcome {
    case nonce(String)
    case failed(FPResult)
}

/// fpchecker client for iOS and macOS.
///
/// ```swift
/// let checker = FingerPrintChecker(config: FPConfig(publishableKey: "pk_...", sealKey: "..."))
/// switch await checker.identify() {
/// case .success(let result): sendToBackend(result.attestation)   // verify server-side!
/// case .failure(let reason, _): print("identify failed: \(reason)")
/// }
/// ```
public final class FingerPrintChecker: Sendable {
    static let requestTimeout: TimeInterval = 10
    static let appAttestTimeout: Double = 20

    private let config: FPConfig
    private let platform: FPPlatform
    private let transport: HTTPTransport
    private let collector: SignalCollecting
    private let appAttest: AppAttestCoordinator?
    private let lock = AsyncLock()

    public convenience init(config: FPConfig) {
        self.init(
            config: config, platform: .current, transport: URLSessionTransport(),
            collector: SystemSignalCollector(),
            appAttest: config.useAppAttest
                ? AppAttestCoordinator(
                    service: SystemAppAttestService(), store: KeychainAppAttestKeyStore(),
                    backoff: UserDefaultsBackoffStore())
                : nil)
    }

    init(
        config: FPConfig, platform: FPPlatform, transport: HTTPTransport,
        collector: SignalCollecting, appAttest: AppAttestCoordinator?
    ) {
        self.config = config
        self.platform = platform
        self.transport = transport
        self.collector = collector
        self.appAttest = appAttest
    }

    /// Fetches a challenge, collects and seals the device signals, and asks the server for the identity.
    /// Calls are serialised. Never throws: every problem is reported as ``FPResult/failure(reason:httpStatus:)``.
    public func identify() async -> FPResult {
        await lock.acquire()
        let result = await run()
        await lock.release()
        return result
    }

    /// `retryUnknownKey`: an assertion the server does not know (it lost or never kept the key) is retried
    /// once with a fresh nonce, so the coordinator attests a new key and the caller never sees an
    /// unattested score for it.
    private func run(retryUnknownKey: Bool = true) async -> FPResult {
        if let difficulty = config.powDifficulty, !ProofOfWork.validBits.contains(difficulty) {
            return .failure(reason: "bad_config", httpStatus: 0)
        }
        let nonce: String
        switch await fetchNonce() {
        case .nonce(let value): nonce = value
        case .failed(let failure): return failure
        }

        let signals = await collector.collect(useDeviceCheck: config.useDeviceCheck)
        guard ComponentRules.validate(platform: platform, components: signals.components).isEmpty else {
            return .failure(reason: "no_device_id", httpStatus: 0)
        }

        let canonical = Canonical.payload(nonce: nonce, components: signals.components)
        var body: [String: Any] = [
            "platform": platform.rawValue,
            "nonce": nonce,
            "sig": Canonical.seal(sealKey: config.sealKey, canonical: canonical),
            "components": signals.components.map { ["key": $0.key, "value": $0.value] },
            "agentVersion": platform.agentVersion,
        ]
        if let difficulty = config.powDifficulty {
            let solved = await Task.detached(priority: .userInitiated) {
                ProofOfWork.solve(nonce: nonce, bits: difficulty)
            }.value
            if let solved { body["pow"] = solved }
        }
        if let token = signals.deviceCheckToken { body["deviceCheckToken"] = token }

        var proof: AppAttestProof?
        if let appAttest {
            let hash = Canonical.clientDataHash(canonical: canonical)
            proof = await withDeadline(seconds: Self.appAttestTimeout) { await appAttest.makeProof(clientDataHash: hash) } ?? nil
            if let proof { body["proof"] = proof.json }
        }

        let result = await postIdentify(body)
        if let proof, let appAttest {
            var status: String?
            if case .success(let success) = result { status = success.proofStatus }
            appAttest.recordOutcome(proof: proof, proofStatus: status)
            if retryUnknownKey, proof.kind == .assertion, status == "unknown_key" {
                return await run(retryUnknownKey: false)
            }
        }
        return result
    }

    private func request(path: String, query: [URLQueryItem] = []) -> URLRequest? {
        guard var components = URLComponents(
            url: config.baseURL.appendingPathComponent(path), resolvingAgainstBaseURL: false)
        else { return nil }
        if !query.isEmpty { components.queryItems = query }
        guard let url = components.url else { return nil }
        var request = URLRequest(url: url, timeoutInterval: Self.requestTimeout)
        request.setValue(config.publishableKey, forHTTPHeaderField: "X-Publishable-Key")
        return request
    }

    private func fetchNonce() async -> NonceOutcome {
        let query = config.powDifficulty.map { [URLQueryItem(name: "difficulty", value: String($0))] } ?? []
        guard let request = request(path: "v1/challenge", query: query) else {
            return .failed(.failure(reason: "bad_config", httpStatus: 0))
        }
        do {
            let (data, status) = try await transport.send(request)
            guard status == 200, let nonce = ResponseParser.parseNonce(data) else {
                return .failed(.failure(reason: "challenge_failed", httpStatus: status))
            }
            return .nonce(nonce)
        } catch {
            return .failed(.failure(reason: "network", httpStatus: 0))
        }
    }

    private func postIdentify(_ body: [String: Any]) async -> FPResult {
        guard var request = request(path: "v1/identify"),
              let payload = try? JSONSerialization.data(withJSONObject: body)
        else { return .failure(reason: "bad_config", httpStatus: 0) }
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = payload
        do {
            let (data, status) = try await transport.send(request)
            return ResponseParser.parseIdentify(data, httpStatus: status)
        } catch {
            return .failure(reason: "network", httpStatus: 0)
        }
    }
}
