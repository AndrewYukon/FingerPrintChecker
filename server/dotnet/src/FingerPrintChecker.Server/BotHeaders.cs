namespace FingerPrintChecker.Server;

/// <summary>Placeholder until the header allowlist lands; replaced wholesale by the bot-headers task.</summary>
internal static class BotHeaders
{
    internal static IReadOnlyDictionary<string, string> Filter(IReadOnlyDictionary<string, string> headers) => headers;
}
