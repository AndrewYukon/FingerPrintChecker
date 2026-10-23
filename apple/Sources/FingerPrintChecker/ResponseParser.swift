import Foundation

enum ResponseParser {
    /// Parses a challenge response; `nil` when there is no usable nonce.
    static func parseNonce(_ body: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let nonce = json["nonce"] as? String, !nonce.isEmpty
        else { return nil }
        return nonce
    }

    static func parseIdentify(_ body: Data, httpStatus: Int) -> FPResult {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            return .failure(reason: "bad_response", httpStatus: httpStatus)
        }
        let ok = (json["ok"] as? Bool) ?? false
        guard ok, let visitorId = json["visitorId"] as? String, !visitorId.isEmpty else {
            let reason = (json["reason"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "bad_response"
            return .failure(reason: reason, httpStatus: httpStatus)
        }
        return .success(FPSuccess(
            visitorId: visitorId,
            trustScore: (json["trustScore"] as? NSNumber)?.intValue ?? 0,
            identityConfidence: (json["identityConfidence"] as? NSNumber)?.intValue ?? 0,
            isNew: (json["isNew"] as? Bool) ?? false,
            attestation: attestationString(json["attestation"]),
            trustDeductions: (json["trustDeductions"] as? [Any])?.compactMap { $0 as? String } ?? [],
            shadowDeductions: (json["shadowDeductions"] as? [Any])?.compactMap { $0 as? String } ?? [],
            proofStatus: json["proofStatus"] as? String,
            raw: body))
    }

    /// The attestation as a string: used as is when it is one, re-serialised as JSON otherwise.
    private static func attestationString(_ value: Any?) -> String? {
        switch value {
        case nil, is NSNull: return nil
        case let string as String: return string
        case let object?:
            guard JSONSerialization.isValidJSONObject(object),
                  let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            else { return nil }
            return String(data: data, encoding: .utf8)
        }
    }

    // MARK: v2

    /// Parses a v2 challenge response; `nil` when there is no usable challenge.
    static func parseChallenge(_ body: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              (json["ok"] as? Bool) == true,
              let challenge = json["challenge"] as? String, !challenge.isEmpty
        else { return nil }
        return challenge
    }

    /// The server's `error` / `reason` string of a failure body, if any.
    static func errorReason(_ body: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { return nil }
        return [json["error"], json["reason"]].lazy.compactMap { $0 as? String }.first { !$0.isEmpty }
    }

    /// A success without a non-empty string `attestation` is a failure.
    static func parseIdentifyV2(_ body: Data, httpStatus: Int) -> FPResultV2 {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            return .failure(reason: "bad_response", httpStatus: httpStatus)
        }
        guard (json["ok"] as? Bool) == true, let attestation = json["attestation"] as? String, !attestation.isEmpty
        else {
            let reason = errorReason(body) ?? "bad_response"
            return .failure(reason: reason, httpStatus: httpStatus)
        }
        func strings(_ key: String) -> [String]? { (json[key] as? [Any])?.compactMap { $0 as? String } }
        return .success(FPSuccessV2(
            attestation: attestation,
            expiresIn: (json["expiresIn"] as? NSNumber)?.intValue,
            proofStatus: json["proofStatus"] as? String,
            visitorId: json["visitorId"] as? String,
            trustScore: (json["trustScore"] as? NSNumber)?.intValue,
            identityConfidence: (json["identityConfidence"] as? NSNumber)?.intValue,
            isNew: json["isNew"] as? Bool,
            trustDeductions: strings("trustDeductions"),
            shadowDeductions: strings("shadowDeductions"),
            rulesVersion: json["rulesVersion"] as? String,
            raw: body))
    }
}
