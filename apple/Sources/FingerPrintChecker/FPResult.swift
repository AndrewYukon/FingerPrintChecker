import Foundation

/// Data returned by a successful identify call.
public struct FPSuccess: Sendable, Equatable {
    public let visitorId: String
    public let trustScore: Int
    public let identityConfidence: Int
    public let isNew: Bool
    /// Opaque token to forward to YOUR backend, which must verify it with the fpchecker API.
    /// Never make entitlement decisions from the other fields on the device.
    public let attestation: String?
    public let trustDeductions: [String]
    /// `none`, `unconfigured`, `wrong_platform`, `unavailable`, `checked` or `unknown_key`.
    public let proofStatus: String?
    /// The unmodified response body.
    public let raw: Data

    public init(
        visitorId: String, trustScore: Int, identityConfidence: Int, isNew: Bool,
        attestation: String?, trustDeductions: [String], proofStatus: String?, raw: Data
    ) {
        self.visitorId = visitorId
        self.trustScore = trustScore
        self.identityConfidence = identityConfidence
        self.isNew = isNew
        self.attestation = attestation
        self.trustDeductions = trustDeductions
        self.proofStatus = proofStatus
        self.raw = raw
    }
}

/// Outcome of ``FingerPrintChecker/identify()``.
public enum FPResult: Sendable, Equatable {
    case success(FPSuccess)
    /// `reason` is a server reason code (`bad_request`, `seal_invalid`, ...) or one of the client-side
    /// codes `network`, `challenge_failed`, `bad_response`, `no_device_id`, `bad_config`.
    /// `httpStatus` is 0 when no HTTP response was received.
    case failure(reason: String, httpStatus: Int)
}
