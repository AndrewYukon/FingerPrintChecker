namespace FingerPrintChecker.Server;

/// <summary>
/// A redirect would forward X-Secret-Key to another origin: any 3xx becomes a network_error. The Location header
/// is never read, so nothing is ever requested from the redirect target.
/// </summary>
internal sealed class RedirectRefusingHandler : DelegatingHandler
{
    public RedirectRefusingHandler(HttpMessageHandler inner)
        : base(inner)
    {
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var status = (int)response.StatusCode;
        if (status >= 300 && status < 400)
        {
            response.Dispose();
            throw new FpCheckerApiException(0, "network_error");
        }

        return response;
    }
}
