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
/// let checker = FingerPrintChecker(config: FPConfig(publishableKey: "pk_..."))
/// // Protocol v2: your backend mints `intentToken` with POST /v2/intents (secret key).
/// switch await checker.identify(intentToken: intentToken) {
/// case .success(let result): sendToBackend(result.attestation)   // opaque, forward unchanged
/// case .failure(let reason, _): print("identify failed: \(reason)")
/// }
/// // Protocol v1 (needs `sealKey`): `await checker.identify()` returns an ``FPResult``.
/// ```
public final class FingerPrintChecker: Sendable {
    static let requestTimeout: TimeInterval = 10
    static let appAttestTimeout: Double = 20

    let config: FPConfig
    let platform: FPPlatform
    let transport: HTTPTransport
    let collector: SignalCollecting
    let appAttest: AppAttestCoordinator?
    let lock = AsyncLock()

    public convenience init(config: FPConfig) {
        self.init(
            config: config, platform: .current, transport: URLSessionTransport(),
            collector: SystemSignalCollector(integrityProbes: config.integrityProbes),
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
    ///
    /// `linkedId` (1 to 256 characters, no control characters) and `tags` (a JSON object of at most 4096 bytes,
    /// nested at most 3 levels, an array counting as a level) are stored on the event this call writes; `nil` sends
    /// nothing. A value that breaks a rule fails with `invalid_linked_id` / `invalid_tags` before any request.
    public func identify(linkedId: String? = nil, tags: [String: Any]? = nil) async -> FPResult {
        let fields: EventFields
        switch EventFields.validate(linkedId: linkedId, tags: tags) {
        case .success(let valid): fields = valid
        case .failure(let error): return .failure(reason: error.reason, httpStatus: 0)
        }
        await lock.acquire()
        let result = await run(fields: fields)
        await lock.release()
        return result
    }

    /// `retryUnknownKey`: an assertion the server does not know (it lost or never kept the key) is retried
    /// once with a fresh nonce, so the coordinator attests a new key and the caller never sees an
    /// unattested score for it.
    private func run(fields: EventFields, retryUnknownKey: Bool = true) async -> FPResult {
        if let difficulty = config.powDifficulty, !ProofOfWork.validBits.contains(difficulty) {
            return .failure(reason: "bad_config", httpStatus: 0)
        }
        guard let sealKey = config.sealKey, !sealKey.isEmpty else {
            return .failure(reason: "seal_key_missing", httpStatus: 0)
        }
        // Probes (300 ms budget) overlap the network round trip instead of following it. On an early failure the
        // task is simply not awaited; it is bounded and its result is dropped.
        let collection = Task { [collector, config] in await collector.collect(useDeviceCheck: config.useDeviceCheck) }
        let nonce: String
        switch await fetchNonce() {
        case .nonce(let value): nonce = value
        case .failed(let failure):
            collection.cancel()
            return failure
        }

        let signals = await collection.value
        guard ComponentRules.validate(platform: platform, components: signals.components).isEmpty else {
            return .failure(reason: "no_device_id", httpStatus: 0)
        }

        let canonical = Canonical.payload(nonce: nonce, components: signals.components)
        var body: [String: Any] = [
            "platform": platform.rawValue,
            "nonce": nonce,
            "sig": Canonical.seal(sealKey: sealKey, canonical: canonical),
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
        fields.apply(to: &body)  // beside the signed fields, never inside them

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
                return await run(fields: fields, retryUnknownKey: false)
            }
        }
        return result
    }

    func request(path: String, query: [URLQueryItem] = []) -> URLRequest? {
        guard var components = URLComponents(
            url: config.baseURL.appendingPathComponent(path), resolvingAgainstBaseURL: false)
        else { return nil }
        if !query.isEmpty {
            // Strict encoding: URLComponents leaves '+' and '&' in values alone, which would corrupt a token.
            components.percentEncodedQueryItems = query.map {
                URLQueryItem(name: $0.name, value: $0.value.map(Self.encodeQueryValue))
            }
        }
        guard let url = components.url else { return nil }
        var request = URLRequest(url: url, timeoutInterval: Self.requestTimeout)
        request.setValue(config.publishableKey, forHTTPHeaderField: "X-Publishable-Key")
        return request
    }

    private static func encodeQueryValue(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: CharacterSet(charactersIn:
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")) ?? value
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
