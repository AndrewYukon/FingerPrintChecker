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
}
