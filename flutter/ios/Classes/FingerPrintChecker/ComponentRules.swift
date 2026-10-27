import Foundation

/// Platform readings before normalisation. `nil` means "could not be obtained".
struct RawSignals: Sendable {
    var keychainId: String?
    var idfv: String?
    var platformUuid: String?
    var timezone: String?
    var model: String?
    var osVersion: String?
    var simulator: Bool?
    /// Base64 DeviceCheck token as sent in the body field `deviceCheckToken`.
    var deviceCheckToken: String?
    /// `<probeVersion>:<fired csv>:<unavailable csv>`; `nil` when no probe value was produced.
    var integrity: String?

    init(
        keychainId: String? = nil, idfv: String? = nil, platformUuid: String? = nil,
        timezone: String? = nil, model: String? = nil, osVersion: String? = nil,
        simulator: Bool? = nil, deviceCheckToken: String? = nil, integrity: String? = nil
    ) {
        self.keychainId = keychainId
        self.idfv = idfv
        self.platformUuid = platformUuid
        self.timezone = timezone
        self.model = model
        self.osVersion = osVersion
        self.simulator = simulator
        self.deviceCheckToken = deviceCheckToken
        self.integrity = integrity
    }
}

/// Client-side mirror of the server's component formats. The server rejects the whole request on a
/// wrong format, so values are validated here and unobtainable ones are omitted.
enum ComponentRules {
    static let maxValue = 256
    static let maxModel = 64
    static let maxOSVersion = 32

    private static let uuidPattern = try! NSRegularExpression(
        pattern: "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
    private static let hex64Pattern = try! NSRegularExpression(pattern: "^[0-9a-f]{64}$")

    private static func matches(_ regex: NSRegularExpression, _ value: String) -> Bool {
        let range = NSRange(value.startIndex..., in: value)
        return regex.firstMatch(in: value, options: [], range: range) != nil
    }

    /// Returns the UUID unchanged when well formed and not all zeros; otherwise `nil`.
    static func normalizeUUID(_ raw: String?) -> String? {
        guard let value = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
              matches(uuidPattern, value),
              value.contains(where: { $0 != "0" && $0 != "-" })
        else { return nil }
        return value
    }

    /// Truncates without cutting a surrogate pair or grapheme; `nil` for empty input.
    /// `|` becomes `/`: the server refuses free text containing the v1 separator.
    static func optionalText(_ raw: String?, max: Int) -> String? {
        guard let raw, !raw.isEmpty else { return nil }
        var out = ""
        var count = 0
        for character in raw.replacingOccurrences(of: "|", with: "/") {
            let length = String(character).utf16.count
            if count + length > max { break }
            out.append(character)
            count += length
        }
        return out.isEmpty ? nil : out
    }

    /// `hex(SHA-256(UTF-8(token)))` of the base64 DeviceCheck token string.
    static func deviceCheckHash(token: String) -> String {
        FPCrypto.hex(FPCrypto.sha256(utf8: token))
    }

    /// Assemble the component list from raw readings, omitting everything unobtainable or invalid.
    static func build(platform: FPPlatform, raw: RawSignals) -> [FPComponent] {
        var out = [FPComponent]()
        func add(_ name: String, _ value: String?) {
            if let value { out.append(FPComponent(key: platform.key(name), value: value)) }
        }
        switch platform {
        case .ios:
            add("keychainId", normalizeUUID(raw.keychainId))
            add("idfv", normalizeUUID(raw.idfv))
        case .macos:
            add("platformUuid", normalizeUUID(raw.platformUuid))
            add("keychainId", normalizeUUID(raw.keychainId))
        }
        add("timezone", optionalText(raw.timezone, max: maxValue))
        add("model", optionalText(raw.model, max: maxModel))
        add("osVersion", optionalText(raw.osVersion, max: maxOSVersion))
        if platform == .ios, let simulator = raw.simulator { add("simulator", simulator ? "true" : "false") }
        if let token = raw.deviceCheckToken, !token.isEmpty { add("deviceCheck", deviceCheckHash(token: token)) }
        if let integrity = raw.integrity, integrityErrors(platform: platform, key: platform.key("integrity"), value: integrity).isEmpty {
            add("integrity", integrity)
        }
        return out
    }

    private static let integrityPattern = try! NSRegularExpression(
        pattern: "^[0-9]{1,3}:([a-z_]+(,[a-z_]+)*)?:([a-z_]+(,[a-z_]+)*)?$")

    /// Mirrors the server: version >= 1, this platform's codes only, no duplicates, fired and unavailable disjoint.
    static func integrityErrors(platform: FPPlatform, key: String, value: String) -> [String] {
        guard matches(integrityPattern, value) else { return ["\(key) bad format"] }
        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        let fired = parts[1].split(separator: ",").map(String.init)
        let unavailable = parts[2].split(separator: ",").map(String.init)
        let known = Set(IntegrityProbes.codes(for: platform))
        let bad = Set(fired).count != fired.count || Set(unavailable).count != unavailable.count
            || !Set(fired).isSubset(of: known) || !Set(unavailable).isSubset(of: known)
            || !Set(fired).isDisjoint(with: unavailable) || (Int(parts[0]) ?? 0) < 1
        return bad ? ["\(key) bad codes"] : []
    }

    /// Violations (empty when the server would accept the list).
    static func validate(platform: FPPlatform, components: [FPComponent]) -> [String] {
        var errors = [String]()
        var seen = Set<String>()
        let uuidKeys = Set(platform.identityKeys)
        let allowed = uuidKeys.union(["timezone", "model", "osVersion", "deviceCheck"].map(platform.key))
            .union(platform == .ios ? [platform.key("simulator")] : [])
            .union([platform.key("integrity")])
        for component in components {
            let key = component.key, value = component.value
            if !seen.insert(key).inserted { errors.append("duplicate key \(key)") }
            if !allowed.contains(key) { errors.append("unknown key \(key)"); continue }
            if value.utf16.count > maxValue { errors.append("\(key) too long") }
            if uuidKeys.contains(key) {
                if normalizeUUID(value) != value { errors.append("\(key) bad format") }
            } else if key == platform.key("model") {
                if value.isEmpty || value.utf16.count > maxModel { errors.append("\(key) bad length") }
            } else if key == platform.key("osVersion") {
                if value.isEmpty || value.utf16.count > maxOSVersion { errors.append("\(key) bad length") }
            } else if key == platform.key("timezone") {
                if value.isEmpty { errors.append("\(key) empty") }
            } else if key == platform.key("simulator") {
                if value != "true" && value != "false" { errors.append("\(key) bad format") }
            } else if key == platform.key("integrity") {
                errors += integrityErrors(platform: platform, key: key, value: value)
            } else if key == platform.key("deviceCheck") {
                if !matches(hex64Pattern, value) { errors.append("\(key) bad format") }
            }
        }
        if !components.contains(where: { uuidKeys.contains($0.key) }) { errors.append("no identity key") }
        return errors
    }
}
