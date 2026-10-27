<?php

declare(strict_types=1);

namespace FpChecker\Tests;

use FpChecker\Transport;
use Throwable;

final class FakeTransport implements Transport
{
    /** @var list<array{method: string, url: string, headers: array<string, string>, body: ?string, timeout: float}> */
    public array $calls = [];
    /** @var list<array{status: int, headers: array<string, string>, body: string}|Throwable> */
    private array $queue;

    /** @param array{status: int, headers: array<string, string>, body: string}|Throwable ...$responses */
    public function __construct(array|Throwable ...$responses)
    {
        $this->queue = array_values($responses);
    }

    public function send(string $method, string $url, array $headers, ?string $body, float $timeout): array
    {
        $this->calls[] = compact('method', 'url', 'headers', 'body', 'timeout');
        if ($this->queue === []) {
            throw new \AssertionError('no more responses');
        }
        $next = array_shift($this->queue);
        if ($next instanceof Throwable) {
            throw $next;
        }
        return $next;
    }

    /** @param array<string, string> $headers @return array{status: int, headers: array<string, string>, body: string} */
    public static function resp(int $status, string|array|null $body = null, array $headers = []): array
    {
        $raw = $body === null ? '' : (is_string($body) ? $body : json_encode($body, JSON_THROW_ON_ERROR));
        return ['status' => $status, 'headers' => $headers, 'body' => $raw];
    }

    public function header(int $call, string $name): ?string
    {
        foreach ($this->calls[$call]['headers'] as $k => $v) {
            if (strcasecmp($k, $name) === 0) {
                return $v;
            }
        }
        return null;
    }
}
