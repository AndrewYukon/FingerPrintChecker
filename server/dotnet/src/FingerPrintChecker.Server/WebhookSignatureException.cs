namespace FingerPrintChecker.Server;

/// <summary>
/// A webhook signature was refused. <see cref="Code"/> is one of malformed_header, bad_signature, expired, future.
/// The message carries only the code, never the secret or the signature.
/// </summary>
public sealed class WebhookSignatureException : Exception
{
    public WebhookSignatureException(string code)
        : base("Webhook signature error: " + code)
    {
        Code = code;
    }

    public string Code { get; }
}
