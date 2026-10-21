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
}
