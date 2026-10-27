namespace FingerPrintChecker.Server;

/// <summary>Client configuration. <see cref="ToString"/> never includes the keys.</summary>
public sealed class FpCheckerOptions
{
    /// <summary>Sent only in the <c>X-Secret-Key</c> header. Printable ASCII, no control characters.</summary>
    public required string SecretKey { get; init; }

    /// <summary>Needed for <c>GetChallengeAsync</c> and <c>IdentifyAsync</c>. Sent only in <c>X-Publishable-Key</c>.</summary>
    public string? PublishableKey { get; init; }

    /// <summary>https, or http for localhost, 127.0.0.1 and [::1] only.</summary>
    public string BaseUrl { get; init; } = "https://api.fpchecker.com";

    /// <summary>Per attempt; must be positive.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    public override string ToString() => "FpCheckerOptions(BaseUrl=" + BaseUrl + ")";
}
