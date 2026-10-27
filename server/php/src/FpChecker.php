<?php

declare(strict_types=1);

namespace FpChecker;

use InvalidArgumentException;
use JsonException;
use LogicException;
use Throwable;

/** Server client for the FpChecker API. The secret key goes only in the X-Secret-Key header. */
final class FpChecker
{
    public const DEFAULT_BASE_URL = 'https://api.fpchecker.com';

    private const MAX_RETRIES = 2;
    private const MAX_DELAY = 10.0;
    private const LOOPBACK = ['localhost', '127.0.0.1', '[::1]', '::1'];
    private const USER_AGENT = 'fpchecker-php/0.1.0';

    private Secret $secretKey;
    private ?Secret $publishableKey;
    private string $baseUrl;
    private float $timeout;
    private Transport $transport;
    /** @var callable(float): void */
    private $sleep;

    /**
     * @param int|float $timeout seconds, positive and finite
     */
    public function __construct(
        #[\SensitiveParameter] string $secretKey,
        #[\SensitiveParameter] ?string $publishableKey = null,
        string $baseUrl = self::DEFAULT_BASE_URL,
        mixed $timeout = 10.0,
    ) {
        if ($secretKey === '') {
            throw new InvalidArgumentException('FpChecker: secretKey is required');
        }
        self::checkHeaderValue('secretKey', $secretKey);
        if ($publishableKey !== null) {
            if ($publishableKey === '') {
                throw new InvalidArgumentException('FpChecker: publishableKey must be a non-empty string');
            }
            self::checkHeaderValue('publishableKey', $publishableKey);
        }
        if (!(is_int($timeout) || is_float($timeout)) || !is_finite((float) $timeout) || $timeout <= 0) {
            throw new InvalidArgumentException('FpChecker: timeout must be a positive finite number');
        }
        $this->secretKey = new Secret($secretKey);
        $this->publishableKey = $publishableKey === null ? null : new Secret($publishableKey);
        $this->baseUrl = self::validateBaseUrl($baseUrl);
        $this->timeout = (float) $timeout;
        $this->transport = new CurlTransport();
        $this->sleep = static function (float $seconds): void {
            usleep((int) round($seconds * 1_000_000));
        };
    }

    /**
     * Test seam: inject a transport and a sleep function. Public constructors never accept a transport.
     *
     * @internal
     * @param callable(float): void $sleep
     */
    public static function withTransport(
        Transport $transport,
        callable $sleep,
        #[\SensitiveParameter] string $secretKey,
        #[\SensitiveParameter] ?string $publishableKey = null,
        string $baseUrl = self::DEFAULT_BASE_URL,
        mixed $timeout = 10.0,
    ): self {
        $client = new self($secretKey, $publishableKey, $baseUrl, $timeout);
        $client->transport = $transport;
        $client->sleep = $sleep;
        return $client;
    }

    /** @return array<string, string> */
    public function __debugInfo(): array
    {
        return ['baseUrl' => $this->baseUrl];
    }

    public function __toString(): string
    {
        return 'FpChecker(baseUrl=' . $this->baseUrl . ')';
    }

    /** @return array<string, mixed> */
    public function __serialize(): array
    {
        throw new LogicException('FpChecker: clients hold a secret key and cannot be serialized');
    }

    // --- validation ---

    private static function checkHeaderValue(string $name, string $value): void
    {
        if (preg_match('/[^\x20-\x7E]/', $value) === 1) {
            throw new InvalidArgumentException(
                'FpChecker: ' . $name . ' must be printable ASCII (no control characters)',
            );
        }
    }

    private static function validateBaseUrl(string $raw): string
    {
        $parts = parse_url($raw);
        $host = is_array($parts) ? ($parts['host'] ?? '') : '';
        if ($host === '') {
            throw new InvalidArgumentException('FpChecker: baseUrl is not a valid URL');
        }
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $loopback = in_array(strtolower($host), self::LOOPBACK, true);
        if ($scheme !== 'https' && !($scheme === 'http' && $loopback)) {
            throw new InvalidArgumentException(
                'FpChecker: baseUrl must be https (http only for localhost, 127.0.0.1, [::1])',
            );
        }
        return rtrim($raw, '/');
    }

    // --- operations (method name = operationId) ---

    /** @param array<mixed>|object $body */
    public function createIntent(array|object $body): array
    {
        return $this->call('POST', '/v2/intents', null, $body);
    }

    /** @param array<string, mixed> $query */
    public function getChallenge(array $query): array
    {
        return $this->call('GET', '/v2/challenge', $query, null, true);
    }

    /** @param array<mixed>|object $body */
    public function identify(array|object $body): array
    {
        return $this->call('POST', '/v2/identify', null, $body, true);
    }

    /** @param array<mixed>|object $body */
    public function checkEligibility(array|object $body): array
    {
        return $this->call('POST', '/v1/eligibility', null, $body);
    }

    /** @param array<mixed>|object $body */
    public function releaseEligibility(array|object $body): array
    {
        return $this->call('POST', '/v1/eligibility/release', null, $body);
    }

    /**
     * Classify a request your backend received. Not charged, writes no event. Send $url as the visitor
     * requested it (original host and scheme). Headers are filtered with BotHeaders::filter.
     *
     * @param array<string, string> $headers
     */
    public function botCheck(string $method, string $url, string $ip, array $headers): array
    {
        $filtered = BotHeaders::filter($headers);
        return $this->call('POST', '/v1/bot-check', null, [
            'method' => $method,
            'url' => $url,
            'ip' => $ip,
            'headers' => $filtered === [] ? new \stdClass() : $filtered,
        ]);
    }

    /** @param array<mixed>|object $body */
    public function checkQuota(array|object $body): array
    {
        return $this->call('POST', '/v1/quota', null, $body);
    }

    /** @param array<mixed>|object $body */
    public function bindSubject(array|object $body): array
    {
        return $this->call('POST', '/v1/subjects/bind', null, $body);
    }

    /** @param array<mixed>|object $body */
    public function relateSubjects(array|object $body): array
    {
        return $this->call('POST', '/v1/subjects/relation', null, $body);
    }

    /** @param array<mixed>|object $body */
    public function sendFeedback(array|object $body): array
    {
        return $this->call('POST', '/v1/feedback', null, $body);
    }

    /** @param array<string, mixed>|null $query */
    public function getClaimFlags(?array $query = null): array
    {
        return $this->call('GET', '/v1/claims/flags', $query);
    }

    /** @param array<string, mixed>|null $query */
    public function searchEvents(?array $query = null): array
    {
        return $this->call('GET', '/v1/events', $query);
    }

    public function getEvent(string $eventId): array
    {
        return $this->call('GET', '/v1/events/' . self::pathId($eventId));
    }

    /** @param array<mixed>|object $body */
    public function updateEvent(string $eventId, array|object $body): array
    {
        return $this->call('PATCH', '/v1/events/' . self::pathId($eventId), null, $body);
    }

    public function getVisitor(string $visitorId): array
    {
        return $this->call('GET', '/v1/visitors/' . self::pathId($visitorId));
    }

    public function deleteVisitor(string $visitorId): array
    {
        return $this->call('DELETE', '/v1/visitors/' . self::pathId($visitorId));
    }

    public function getHealth(): array
    {
        return $this->call('GET', '/health', null, null, false, false);
    }

    public function getStatus(): array
    {
        return $this->call('GET', '/status', null, null, false, false);
    }

    // --- encoding ---

    /** quote(value, safe="") for a path segment; ids that could change the route are refused. */
    private static function pathId(string $id): string
    {
        if ($id === '' || $id === '.' || $id === '..') {
            throw new InvalidArgumentException("FpChecker: id must be a non-empty string and not '.' or '..'");
        }
        return rawurlencode($id); // unreserved is A-Za-z0-9 and -_.~ , same as Python quote
    }

    /** Python quote_plus semantics: rawurlencode, with space as '+'. */
    private static function encodePlus(string $value): string
    {
        return str_replace('%20', '+', rawurlencode($value));
    }

    /** @internal */
    public static function queryString(?array $query): string
    {
        if ($query === null || $query === []) {
            return '';
        }
        $parts = [];
        foreach ($query as $key => $value) {
            if ($value === null) {
                continue;
            }
            if ($value === true) {
                $text = 'true';
            } elseif ($value === false) {
                $text = 'false';
            } elseif (is_scalar($value) || $value instanceof \Stringable) {
                $text = (string) $value;
            } else {
                throw new InvalidArgumentException('FpChecker: query values must be scalar');
            }
            $parts[] = self::encodePlus((string) $key) . '=' . self::encodePlus($text);
        }
        return $parts === [] ? '' : '?' . implode('&', $parts);
    }

    // --- response parsing ---

    private static function parseJson(string $raw): mixed
    {
        if ($raw === '') {
            return null;
        }
        try {
            return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }
    }

    private static function errorCode(mixed $body): ?string
    {
        if (!is_array($body)) {
            return null;
        }
        $code = $body['error'] ?? null;
        if ($code === null) {
            $code = $body['reason'] ?? null;
        }
        return is_string($code) ? $code : null;
    }

    private static function parseRetryAfter(?string $value): ?int
    {
        if ($value === null) {
            return null;
        }
        $v = trim($value);
        return preg_match('/\A[0-9]{1,9}\z/', $v) === 1 ? (int) $v : null;
    }

    // --- transport ---

    /**
     * @param array<string, mixed>|null $query
     * @param array<mixed>|object|null $body
     */
    private function call(
        string $method,
        string $path,
        ?array $query = null,
        array|object|null $body = null,
        bool $publishable = false,
        bool $auth = true,
    ): array {
        $url = $this->baseUrl . $path . self::queryString($query);
        $headers = ['Accept' => 'application/json', 'User-Agent' => self::USER_AGENT];
        if ($publishable) {
            if ($this->publishableKey === null) {
                throw new LogicException('FpChecker: publishableKey is required for this operation');
            }
            $headers['X-Publishable-Key'] = $this->publishableKey->reveal();
        } elseif ($auth) {
            $headers['X-Secret-Key'] = $this->secretKey->reveal();
        }
        $data = null;
        if ($body !== null) {
            $data = $body === [] ? '{}' : $this->encodeBody($body);
            $headers['Content-Type'] = 'application/json';
        }
        $maxRetries = $method === 'GET' ? self::MAX_RETRIES : 0;

        $attempt = 0;
        while (true) {
            $res = null;
            $failed = false;
            $timedOut = false;
            try {
                $res = $this->transport->send($method, $url, $headers, $data, $this->timeout);
                if ($res['status'] >= 300 && $res['status'] < 400) {
                    // A redirect would forward X-Secret-Key to another origin: never follow, never read Location.
                    $failed = true;
                }
            } catch (TransportException $e) {
                $failed = true;
                $timedOut = $e->isTimeout();
            } catch (Throwable) {
                // Any other failure (including Errors) is a network failure. Not chained: its trace could
                // carry the request headers as arguments.
                $failed = true;
            }

            if ($failed) {
                if ($attempt < $maxRetries) {
                    ($this->sleep)(min(0.5 * (2 ** $attempt), self::MAX_DELAY));
                    $attempt++;
                    continue;
                }
                throw new FpCheckerApiError(0, $timedOut ? 'timeout' : 'network_error', null, null);
            }

            $status = $res['status'];
            $parsed = self::parseJson($res['body']);
            if ($status >= 200 && $status < 300) {
                return is_array($parsed) ? $parsed : [];
            }

            $retryAfter = self::parseRetryAfter(array_change_key_case($res['headers'])['retry-after'] ?? null);
            if (($status === 429 || $status >= 500) && $attempt < $maxRetries) {
                $wait = $retryAfter ?? 0.5 * (2 ** $attempt);
                ($this->sleep)(min($wait, self::MAX_DELAY));
                $attempt++;
                continue;
            }
            throw new FpCheckerApiError($status, self::errorCode($parsed), $retryAfter, $parsed);
        }
    }

    /** @param array<mixed>|object $body */
    private function encodeBody(array|object $body): string
    {
        try {
            return json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException) {
            throw new InvalidArgumentException('FpChecker: body is not JSON-serializable');
        }
    }
}
