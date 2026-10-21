import Foundation

/// The Apple platform this build reports as.
enum FPPlatform: String, Sendable {
    case ios
    case macos

    static var current: FPPlatform {
        #if os(macOS)
        return .macos
        #else
        return .ios
        #endif
    }

    var agentVersion: String { "\(rawValue)-\(FPVersion.sdk)" }

    var identityKeys: [String] {
        switch self {
        case .ios: return ["ios.keychainId", "ios.idfv"]
        case .macos: return ["macos.platformUuid", "macos.keychainId"]
        }
    }

    func key(_ name: String) -> String { "\(rawValue).\(name)" }
}
