using System.Text.Json;

namespace FingerPrintChecker.Server;

/// <summary>What the project's ruleset decided. <c>Type</c>: allow | human_check | deny | none (open string).</summary>
public sealed record RuleAction(string Type, string? RuleId = null, string? RuleName = null, long RulesetVersion = 0);

/// <summary>
/// Device-state signals of an android, ios or macos event. Each flag is true (detected), false (checked, nothing
/// found) or null (not checked). Not a guarantee either way. <c>FactoryResetAt</c> is reserved and currently always null.
/// </summary>
public sealed record MobileSignals(
    bool? Emulator = null,
    bool? Attested = null,
    string? Integrity = null,
    bool? Rooted = null,
    bool? Hooked = null,
    bool? Debugger = null,
    bool? DeveloperMode = null,
    bool? Mitm = null,
    bool? Vpn = null,
    bool? LocationSpoofed = null,
    bool? ClonedApp = null,
    string? FactoryResetAt = null);

/// <summary>One entry of the Bot directory. <c>Category</c> and <c>Identity</c> are open strings: treat an unknown category as other.</summary>
public sealed record BotInfo(string Id, string Name, string Provider, string Category, string Identity);

/// <summary>
/// <c>signals.bot</c>. <c>Result</c>: not_detected | good | bad (open; treat an unknown value as bad), null when not
/// checked. <c>Info</c> is null for version 1 events and when the request did not name a directory bot.
/// </summary>
public sealed record BotSignals(string? Result, IReadOnlyList<string> Types, BotInfo? Info);

/// <summary>
/// <c>RuleAction</c> and <c>Proxied</c> are null when the payload lacks them (queued before server 0.45.0);
/// <c>RuleActionPresent</c> tells a JSON null from a missing key.
/// </summary>
public sealed record WebhookEvent(
    string VisitorId,
    bool? Proxied,
    RuleAction? RuleAction,
    bool RuleActionPresent,
    MobileSignals? Mobile,
    IReadOnlyList<string> VpnMethods,
    JsonElement Raw,
    int? SignalsVersion,
    BotSignals? Bot);

/// <summary>Narrowed CheckEligibility response.</summary>
public sealed record EligibilityAnswer(bool Ok, bool? Eligible, string? Action, string? Reason, string? RuleId, JsonElement Raw);
