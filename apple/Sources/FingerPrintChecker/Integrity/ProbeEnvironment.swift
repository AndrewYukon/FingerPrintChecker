import Foundation

/// Everything a probe may read from the device. A protocol so probes are unit-tested with a fake.
/// Readings that cannot be obtained return `nil`, which a probe maps to ``ProbeResult/unavailable``.
protocol ProbeEnvironment: Sendable {
    func fileExists(_ path: String) -> Bool
    /// Tries to create (and immediately delete) a file outside the app sandbox.
    func canWriteOutsideSandbox() -> Bool
    func loadedImageNames() -> [String]
    /// True when something accepts a TCP connection on 127.0.0.1:`port` within `timeout` seconds.
    func canConnectLocal(port: UInt16, timeout: TimeInterval) -> Bool
    func environment(_ name: String) -> String?
    func isTraced() -> Bool
    /// The system proxy settings dictionary (includes `__SCOPED__`), or `nil` when unreadable.
    func proxySettings() -> [String: Any]?
    /// `isSimulatedBySoftware` of the cached location; `nil` when it cannot be read without prompting.
    func locationSimulated() -> Bool?
}
