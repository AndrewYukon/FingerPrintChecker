<?php

declare(strict_types=1);

namespace FpChecker;

/**
 * One HTTP round trip. Implementations must not follow redirects (the client treats any 3xx as a network
 * failure) and must throw TransportException (or any Throwable) on failure.
 *
 * @internal Public constructors never accept a transport: an injected one could follow a redirect and forward
 *           the secret key to another origin.
 */
interface Transport
{
    /**
     * @param array<string, string> $headers
     * @return array{status: int, headers: array<string, string>, body: string}
     */
    public function send(
        string $method,
        string $url,
        #[\SensitiveParameter] array $headers,
        ?string $body,
        float $timeout,
    ): array;
}
