import FingerPrintChecker
import Foundation

/// Internal device/network test: one real claim for round `r<N>` through the demo backend
/// (`<intent URL>/../claim`). It identifies with an intent minted for that round, claims, and when
/// the claim asks for proof of work identifies again with that many bits and claims once more.
enum MatrixClaim {
    struct Answer {
        let action: String
        let reason: String
        let powDifficulty: Int?
    }

    static func isRound(_ round: String) -> Bool {
        round.range(of: #"^r[0-9]{1,3}$"#, options: .regularExpression) != nil
    }

    static func run(round: String, intentURL: URL, config: FPConfig) async -> String {
        let claimURL = intentURL.deletingLastPathComponent().appendingPathComponent("claim")
        var answer: Result<Answer, IntentError>
        switch await attestation(round: round, intentURL: intentURL, config: config) {
        case .failure(let e): return "CLAIM \(round): ERROR \(e.reason) (http \(e.httpStatus))"
        case .success(let token): answer = await claim(claimURL, attestation: token, round: round)
        }
        if case .success(let first) = answer, first.action == "pow", let bits = first.powDifficulty {
            var proving = config
            proving.powDifficulty = bits
            switch await attestation(round: round, intentURL: intentURL, config: proving) {
            case .failure(let e): return "CLAIM \(round): ERROR pow \(e.reason) (http \(e.httpStatus))"
            case .success(let token): answer = await claim(claimURL, attestation: token, round: round)
            }
        }
        switch answer {
        case .success(let a): return "CLAIM \(round): \(a.action.uppercased()) · \(a.reason)"
        case .failure(let e): return "CLAIM \(round): ERROR \(e.reason) (http \(e.httpStatus))"
        }
    }

    /// Identify v2 with an intent minted for this round's claim: the attestation to claim with.
    private static func attestation(round: String, intentURL: URL, config: FPConfig) async -> Result<String, IntentError> {
        switch await DemoConfig.fetchIntent(from: intentURL, round: round) {
        case .failure(let e):
            return .failure(IntentError(reason: "intent \(e.reason)", httpStatus: e.httpStatus))
        case .success(let token):
            switch await FingerPrintChecker(config: config).identify(intentToken: token) {
            case .success(let s): return .success(s.attestation)
            case .failure(let reason, let status): return .failure(IntentError(reason: "identify \(reason)", httpStatus: status))
            }
        }
    }

    private static func claim(_ url: URL, attestation: String, round: String) async -> Result<Answer, IntentError> {
        var request = URLRequest(url: url, timeoutInterval: 15)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["attestation": attestation, "round": round])
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            if let action = body?["action"] as? String, let reason = body?["reason"] as? String {
                return .success(Answer(action: action, reason: reason, powDifficulty: body?["powDifficulty"] as? Int))
            }
            return .failure(IntentError(reason: body?["error"] as? String ?? "bad_response", httpStatus: status))
        } catch {
            return .failure(IntentError(reason: "network", httpStatus: 0))
        }
    }
}
