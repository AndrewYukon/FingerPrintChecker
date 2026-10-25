import Foundation

private enum ChallengeOutcome {
    case challenge(String)
    case failed(FPResultV2)
}

extension FingerPrintChecker {
    /// Protocol v2: fetches a challenge for `intentToken` (minted by your backend with its secret key),
    /// collects the device signals, binds them with App Attest and returns an opaque `attestation` to
    /// forward unchanged to your backend. Calls are serialised. Never throws.
    ///
    /// `linkedId` (1 to 256 characters, no control characters) and `tags` (a JSON object of at most 4096 bytes,
    /// nested at most 3 levels, an array counting as a level) are stored on the event this call writes and the
    /// success carries its `eventId`. `nil` sends nothing. A value that breaks a rule fails with
    /// `invalid_linked_id` / `invalid_tags` before any request.
    public func identify(intentToken: String, linkedId: String? = nil, tags: [String: Any]? = nil) async -> FPResultV2 {
        let fields: EventFields
        switch EventFields.validate(linkedId: linkedId, tags: tags) {
        case .success(let valid): fields = valid
        case .failure(let error): return .failure(reason: error.reason, httpStatus: 0)
        }
        await lock.acquire()
        let result = await runV2(intentToken: intentToken, fields: fields)
        await lock.release()
        return result
    }

    /// `retryUnknownKey` as in v1: the intent is reusable, so the retry fetches a fresh challenge with it.
    private func runV2(intentToken: String, fields: EventFields, retryUnknownKey: Bool = true) async -> FPResultV2 {
        if intentToken.isEmpty { return .failure(reason: "bad_config", httpStatus: 0) }
        if let difficulty = config.powDifficulty, !ProofOfWork.validBits.contains(difficulty) {
            return .failure(reason: "bad_config", httpStatus: 0)
        }
        let challenge: String
        switch await fetchChallengeV2(intentToken: intentToken) {
        case .challenge(let value): challenge = value
        case .failed(let failure): return failure
        }

        let signals = await collector.collect(useDeviceCheck: config.useDeviceCheck)
        guard ComponentRules.validate(platform: platform, components: signals.components).isEmpty else {
            return .failure(reason: "no_device_id", httpStatus: 0)
        }
        let canonical: Data
        do {
            canonical = try CanonicalV2.bytes(
                platform: platform.rawValue, agentVersion: platform.agentVersion,
                challenge: challenge, components: signals.components)
        } catch {
            return .failure(reason: "bad_request", httpStatus: 0)
        }

        var body: [String: Any] = [
            "protocolVersion": 2,
            "platform": platform.rawValue,
            "intentToken": intentToken,
            "challenge": challenge,
            "components": signals.components.map { ["key": $0.key, "value": $0.value] },
            "agentVersion": platform.agentVersion,
        ]
        if let difficulty = config.powDifficulty {
            let solved = await Task.detached(priority: .userInitiated) {
                ProofOfWork.solve(nonce: challenge, bits: difficulty)
            }.value
            if let solved { body["pow"] = solved }
        }
        if let token = signals.deviceCheckToken { body["deviceCheckToken"] = token }
        fields.apply(to: &body)  // beside the signed fields, never inside them

        var proof: AppAttestProof?
        if let appAttest {
            let hash = CanonicalV2.requestBinding(canonical)
            proof = await withDeadline(seconds: Self.appAttestTimeout) { await appAttest.makeProof(clientDataHash: hash) } ?? nil
            if let proof { body["proof"] = proof.json }
        }

        let result = await postIdentifyV2(body)
        if let proof, let appAttest {
            var status: String?
            if case .success(let success) = result { status = success.proofStatus }
            appAttest.recordOutcome(proof: proof, proofStatus: status)
            if retryUnknownKey, proof.kind == .assertion, status == "unknown_key" {
                return await runV2(intentToken: intentToken, fields: fields, retryUnknownKey: false)
            }
        }
        return result
    }

    private func fetchChallengeV2(intentToken: String) async -> ChallengeOutcome {
        var query = [URLQueryItem(name: "intent", value: intentToken)]
        if let difficulty = config.powDifficulty { query.append(URLQueryItem(name: "difficulty", value: String(difficulty))) }
        guard let request = request(path: "v2/challenge", query: query) else {
            return .failed(.failure(reason: "bad_config", httpStatus: 0))
        }
        do {
            let (data, status) = try await transport.send(request)
            guard status == 200, let challenge = ResponseParser.parseChallenge(data) else {
                // The server's error code (`bad_intent`, ...) is more useful than a generic one.
                let reason = ResponseParser.errorReason(data) ?? "challenge_failed"
                return .failed(.failure(reason: reason, httpStatus: status))
            }
            return .challenge(challenge)
        } catch {
            return .failed(.failure(reason: "network", httpStatus: 0))
        }
    }

    private func postIdentifyV2(_ body: [String: Any]) async -> FPResultV2 {
        guard var request = request(path: "v2/identify"),
              let payload = try? JSONSerialization.data(withJSONObject: body)
        else { return .failure(reason: "bad_config", httpStatus: 0) }
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = payload
        do {
            let (data, status) = try await transport.send(request)
            return ResponseParser.parseIdentifyV2(data, httpStatus: status)
        } catch {
            return .failure(reason: "network", httpStatus: 0)
        }
    }
}
