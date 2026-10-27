import Foundation

/// Configuration for ``FingerPrintChecker``.
public struct FPConfig: Sendable {
    /// Base URL of the fpchecker API.
    public var baseURL: URL
    /// Publishable key of your fpchecker project (public by design).
    public var publishableKey: String
    /// Seal key of your fpchecker project; only protocol v1 (`identify()`) needs it. It ships inside the
    /// app, so treat everything the device computes as forgeable. `identify(intentToken:)` needs no secret.
    public var sealKey: String?
    /// Proof-of-work difficulty (8...28) when your project requires it; `nil` otherwise.
    public var powDifficulty: Int?
    /// Attach an App Attest proof when the device supports it.
    public var useAppAttest: Bool
    /// Attach a DeviceCheck token when the device supports it.
    public var useDeviceCheck: Bool
    /// Run the on-device integrity probes (jailbreak, hook, emulator, debugger, proxy, VPN, mock location).
    /// When `false` the SDK still sends the component with every probe marked unavailable, so a project that
    /// switched probes off is distinguishable from a client that stripped them.
    public var integrityProbes: Bool

    public static let defaultBaseURL = URL(string: "https://api.fpchecker.com")!

    public init(
        baseURL: URL = FPConfig.defaultBaseURL,
        publishableKey: String,
        sealKey: String? = nil,
        powDifficulty: Int? = nil,
        useAppAttest: Bool = true,
        useDeviceCheck: Bool = true,
        integrityProbes: Bool = true
    ) {
        self.baseURL = baseURL
        self.publishableKey = publishableKey
        self.sealKey = sealKey
        self.powDifficulty = powDifficulty
        self.useAppAttest = useAppAttest
        self.useDeviceCheck = useDeviceCheck
        self.integrityProbes = integrityProbes
    }
}
