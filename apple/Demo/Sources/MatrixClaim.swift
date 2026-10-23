import FingerPrintChecker
import Foundation

/// Internal device/network test: one real claim for round `r<N>` through the demo backend
/// (`<intent URL>/../claim`). A first claim asks for proof of work: re-identify with that many
/// bits and claim once more.
enum MatrixClaim {
    struct Answer {
        let action: String
        let reason: String
        let powDifficulty: Int?
    }

    static func isRound(_ round: String) -> Bool {
        round.range(of: #"^r[0-9]{1,3}$"#, options: .regularExpression) != nil
    }

    static func run(attestation: String, round: String, intentURL: URL, config: FPConfig) async -> String {
        let claimURL = intentURL.deletingLastPathComponent().appendingPathComponent("claim")
        var answer = await claim(claimURL, attestation: attestation, round: round)
        if case .success(let first) = answer, first.action == "pow", let bits = first.powDifficulty {
            var proving = config
            proving.powDifficulty = bits
            switch await DemoConfig.fetchIntent(from: intentURL) {
            case .failure(let e):
                return "CLAIM \(round): ERROR intent \(e.reason) (http \(e.httpStatus))"
            case .success(let token):
                guard case .success(let s) = await FingerPrintChecker(config: proving).identify(intentToken: token) else {
                    return "CLAIM \(round): ERROR pow_identify_failed"
                }
                answer = await claim(claimURL, attestation: s.attestation, round: round)
            }
        }
        switch answer {
        case .success(let a): return "CLAIM \(round): \(a.action.uppercased()) · \(a.reason)"
        case .failure(let e): return "CLAIM \(round): ERROR \(e.reason) (http \(e.httpStatus))"
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
