import Foundation

/// Data returned by a successful v2 identify call.
public struct FPSuccessV2: Sendable, Equatable {
    /// Opaque token to forward unchanged to YOUR backend, which decides with it. Never empty.
    public let attestation: String
    public let expiresIn: Int?
    /// `none`, `unconfigured`, `wrong_platform`, `unavailable`, `checked` or `unknown_key`.
    public let proofStatus: String?
    /// Only present when the project enabled score details; for display and diagnostics, never for decisions.
    public let visitorId: String?
    public let trustScore: Int?
    public let identityConfidence: Int?
    public let isNew: Bool?
    public let trustDeductions: [String]?
    public let shadowDeductions: [String]?
    public let rulesVersion: String?
    /// Id of the event this identify wrote (read it with your secret key); `nil` from servers that predate events.
    public let eventId: String?
    /// The unmodified response body.
    public let raw: Data

    public init(
        attestation: String, expiresIn: Int? = nil, proofStatus: String? = nil, visitorId: String? = nil,
        trustScore: Int? = nil, identityConfidence: Int? = nil, isNew: Bool? = nil,
        trustDeductions: [String]? = nil, shadowDeductions: [String]? = nil, rulesVersion: String? = nil,
        eventId: String? = nil, raw: Data
    ) {
        self.attestation = attestation
        self.expiresIn = expiresIn
        self.proofStatus = proofStatus
        self.visitorId = visitorId
        self.trustScore = trustScore
        self.identityConfidence = identityConfidence
        self.isNew = isNew
        self.trustDeductions = trustDeductions
        self.shadowDeductions = shadowDeductions
        self.rulesVersion = rulesVersion
        self.eventId = eventId
        self.raw = raw
    }
}

/// Outcome of ``FingerPrintChecker/identify(intentToken:)``.
public enum FPResultV2: Sendable, Equatable {
    case success(FPSuccessV2)
    /// `reason` is the server `reason` / `error` (`bad_intent`, `bad_request`, ...) or one of the client-side
    /// codes `network`, `challenge_failed`, `bad_response`, `no_device_id`, `bad_config`, `bad_request`, `invalid_linked_id`, `invalid_tags`.
    /// `httpStatus` is 0 when no HTTP response was received.
    case failure(reason: String, httpStatus: Int)
}
