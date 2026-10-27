import Foundation

/// Outcome of one probe. `unavailable` means "could not run" (error, timeout, no permission), never "clean".
enum ProbeResult: Sendable {
    case fired, clean, unavailable
}

protocol Probe: Sendable {
    /// Wire code, one of ``IntegrityProbes/codes(for:)``.
    var code: String { get }
    /// May throw; the collector turns any error into ``ProbeResult/unavailable``.
    func run(_ env: ProbeEnvironment) throws -> ProbeResult
}
