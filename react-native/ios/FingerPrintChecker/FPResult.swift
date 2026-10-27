import Foundation

/// Data returned by a successful identify call.
public struct FPSuccess: Sendable, Equatable {
    public let visitorId: String
    public let trustScore: Int?
    public let identityConfidence: Int?
    public let isNew: Bool
    /// Opaque token to forward to YOUR backend, which must verify it with the fpchecker API.
    /// Never make entitlement decisions from the other fields on the device.
    public let attestation: String?
    public let trustDeductions: [String]
    /// Rules that are scored but not yet weighted (shadow mode); for evaluation only.
    public let shadowDeductions: [String]
    /// `none`, `unconfigured`, `wrong_platform`, `unavailable`, `checked` or `unknown_key`.
    public let proofStatus: String?
    /// Id of the event this identify wrote (read it with your secret key); `nil` from servers that predate events.
    public let eventId: String?
    /// Sealed result for your backend to open with the project key (`fpsr1.…`); `nil` when the project has no key or the server predates it.
    public let sealedResult: String?
    /// The unmodified response body.
    public let raw: Data

    public init(
        visitorId: String, trustScore: Int?, identityConfidence: Int?, isNew: Bool,
        attestation: String?, trustDeductions: [String], shadowDeductions: [String] = [],
        proofStatus: String?, eventId: String? = nil, sealedResult: String? = nil, raw: Data
    ) {
        self.visitorId = visitorId
        self.trustScore = trustScore
        self.identityConfidence = identityConfidence
        self.isNew = isNew
        self.attestation = attestation
        self.trustDeductions = trustDeductions
        self.shadowDeductions = shadowDeductions
        self.proofStatus = proofStatus
        self.eventId = eventId
        self.sealedResult = sealedResult
        self.raw = raw
    }
}

/// Outcome of ``FingerPrintChecker/identify()``.
public enum FPResult: Sendable, Equatable {
    case success(FPSuccess)
    /// `reason` is a server reason code (`bad_request`, `seal_invalid`, ...) or one of the client-side
    /// codes `network`, `challenge_failed`, `bad_response`, `no_device_id`, `bad_config`, `invalid_linked_id`, `invalid_tags`.
    /// `httpStatus` is 0 when no HTTP response was received.
    case failure(reason: String, httpStatus: Int)
}
