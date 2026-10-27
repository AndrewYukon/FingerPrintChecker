import Foundation

/// The optional customer-supplied event fields (`linkedId`, `tags`). Mirrors the server's rules so a bad value
/// fails before any network call. They are sent beside the signed fields and are never part of the canonical bytes.
struct EventFields {
    static let linkedIdMax = 256
    static let tagsMaxBytes = 4096
    static let tagsMaxDepth = 3

    let linkedId: String?
    let tags: [String: Any]?

    /// `nil` means "not set" for either field: nothing is sent. On failure the value is the server's reason code
    /// (`invalid_linked_id` or `invalid_tags`).
    static func validate(linkedId: String?, tags: [String: Any]?) -> Result<EventFields, EventFieldsError> {
        if let linkedId, !isValid(linkedId: linkedId) { return .failure(.invalidLinkedId) }
        if let tags, !isValid(tags: tags) { return .failure(.invalidTags) }
        return .success(EventFields(linkedId: linkedId, tags: tags))
    }

    /// Adds the fields that are set to a request body.
    func apply(to body: inout [String: Any]) {
        if let linkedId { body["linkedId"] = linkedId }
        if let tags { body["tags"] = tags }
    }

    private static func isValid(linkedId: String) -> Bool {
        let length = linkedId.utf16.count
        guard length >= 1, length <= linkedIdMax else { return false }
        return !linkedId.unicodeScalars.contains { $0.value <= 0x1f || $0.value == 0x7f }
    }

    private static func isValid(tags: [String: Any]) -> Bool {
        guard withinDepth(tags, depth: 1), JSONSerialization.isValidJSONObject(tags) else { return false }
        // `.withoutEscapingSlashes` so the size is what JSON.stringify (the server's measure) would give.
        guard let data = try? JSONSerialization.data(withJSONObject: tags, options: [.withoutEscapingSlashes]) else {
            return false
        }
        return data.count <= tagsMaxBytes
    }

    /// The tags object is level 1. An object is allowed up to level 3, an array only up to level 2
    /// (its elements are one level deeper), so `{"a": {"b": [1]}}` is refused.
    private static func withinDepth(_ value: Any, depth: Int) -> Bool {
        if let object = value as? [String: Any] {
            return depth <= tagsMaxDepth && object.values.allSatisfy { withinDepth($0, depth: depth + 1) }
        }
        if let array = value as? [Any] {
            return depth < tagsMaxDepth && array.allSatisfy { withinDepth($0, depth: depth + 1) }
        }
        return true
    }
}

enum EventFieldsError: Error, Equatable {
    case invalidLinkedId
    case invalidTags

    var reason: String {
        switch self {
        case .invalidLinkedId: return "invalid_linked_id"
        case .invalidTags: return "invalid_tags"
        }
    }
}
