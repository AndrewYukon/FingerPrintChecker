namespace FingerPrintChecker.Server;

/// <summary>
/// A sealed result could not be opened. <see cref="Code"/> is one of bad_format, unknown_key, decrypt_failed,
/// invalid_key, unsupported_version. The message carries only the code, never key or payload material.
/// </summary>
public sealed class SealedResultException : Exception
{
    public SealedResultException(string code)
        : base("Sealed result error: " + code)
    {
        Code = code;
    }

    public string Code { get; }
}
