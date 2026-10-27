using System.Text.Json;
using System.Text.Json.Serialization;

namespace FingerPrintChecker.Server;

/// <summary>Client configuration. <see cref="ToString"/> never includes the keys.</summary>
public sealed class FpCheckerOptions
{
    /// <summary>
    /// Sent only in the <c>X-Secret-Key</c> header. Printable ASCII, no control characters.
    /// Do not log or serialise the options object: it holds the key (System.Text.Json writes a placeholder instead of the key,
    /// but other serialisers and debuggers will show it).
    /// ([JsonIgnore] cannot be combined with <c>required</c>: System.Text.Json refuses to serialise the type.)
    /// </summary>
    [JsonConverter(typeof(RedactedStringConverter))]
    public required string SecretKey { get; init; }

    /// <summary>Needed for <c>GetChallengeAsync</c> and <c>IdentifyAsync</c>. Sent only in <c>X-Publishable-Key</c>.</summary>
    public string? PublishableKey { get; init; }

    /// <summary>https, or http for localhost, 127.0.0.1 and [::1] only.</summary>
    public string BaseUrl { get; init; } = "https://api.fpchecker.com";

    /// <summary>Per attempt; must be positive.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    public override string ToString() => "FpCheckerOptions(BaseUrl=" + BaseUrl + ")";
}

/// <summary>Writes a fixed placeholder so the secret key never reaches serialised output.</summary>
internal sealed class RedactedStringConverter : JsonConverter<string>
{
    public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => reader.GetString();

    public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options) => writer.WriteStringValue("[redacted]");
}
