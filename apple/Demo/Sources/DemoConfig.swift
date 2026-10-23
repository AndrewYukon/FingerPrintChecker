import FingerPrintChecker
import Foundation

/// Reads the values injected from Config.xcconfig through Info.plist.
enum DemoConfig {
    static func load() -> FPConfig? {
        func value(_ key: String) -> String? {
            let raw = Bundle.main.object(forInfoDictionaryKey: key) as? String
            return raw.flatMap { $0.isEmpty ? nil : $0 }
        }
        guard let pk = value("FPCheckerPublishableKey"), let seal = value("FPCheckerSealKey") else { return nil }
        let baseURL = value("FPCheckerBaseURL").flatMap(URL.init(string:)) ?? FPConfig.defaultBaseURL
        return FPConfig(baseURL: baseURL, publishableKey: pk, sealKey: seal)
    }

    /// Backend endpoint that mints a protocol v2 intent; nil hides "Identify v2".
    static func intentURL() -> URL? {
        (Bundle.main.object(forInfoDictionaryKey: "FPCheckerIntentURL") as? String)
            .flatMap { $0.isEmpty ? nil : URL(string: $0) }
    }

    /// POST to the intent endpoint; the token, or a failure reason for display. With a matrix
    /// `round` the intent is minted for that round's claim (`claim:matrix_<round>`); fp-guard
    /// refuses a claim whose attestation was minted for another purpose.
    static func fetchIntent(from url: URL, round: String? = nil) async -> Result<String, IntentError> {
        var request = URLRequest(url: url, timeoutInterval: 10)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: round.map { ["round": $0] } ?? [:])
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            if status == 200, let token = body?["intentToken"] as? String, !token.isEmpty { return .success(token) }
            return .failure(IntentError(reason: body?["error"] as? String ?? "bad_response", httpStatus: status))
        } catch {
            return .failure(IntentError(reason: "network", httpStatus: 0))
        }
    }
}

struct IntentError: Error {
    let reason: String
    let httpStatus: Int
}
