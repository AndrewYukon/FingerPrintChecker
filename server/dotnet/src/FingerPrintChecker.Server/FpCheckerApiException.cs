using System.Text.Json;

namespace FingerPrintChecker.Server;

/// <summary>
/// A non-2xx answer (Status is the HTTP status) or a transport failure (Status 0, Code "network_error" or
/// "timeout"). Neither the message nor ToString ever contains a key; transport failures carry no inner exception
/// because its message could echo a header value.
/// </summary>
public sealed class FpCheckerApiException : Exception
{
    public FpCheckerApiException(int status, string? code, int? retryAfter = null, JsonElement? body = null)
        : base(BuildMessage(status, code))
    {
        Status = status;
        Code = code;
        RetryAfter = retryAfter;
        Body = body;
    }

    public int Status { get; }

    public string? Code { get; }

    /// <summary>Seconds from the Retry-After header, when it was 1 to 9 digits.</summary>
    public int? RetryAfter { get; }

    /// <summary>The parsed JSON error body, when there was one.</summary>
    public JsonElement? Body { get; }

    private static string BuildMessage(int status, string? code) =>
        "FpChecker API error: status=" + status + " code=" + (code ?? "none");
}
