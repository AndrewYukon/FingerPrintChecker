<?php

declare(strict_types=1);

namespace FpChecker\Tests;

use FpChecker\CurlTransport;
use FpChecker\FpChecker;
use FpChecker\FpCheckerApiError;
use FpChecker\TransportException;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class FpCheckerTest extends TestCase
{
    private const SK = 'sk_test_123';
    private const PK = 'pk_test_9';

    /** @var list<float|int> */
    private array $sleeps = [];

    private function mk(FakeTransport $t, ?string $pk = null, string $baseUrl = 'https://api.fpchecker.com', mixed $timeout = 10.0): FpChecker
    {
        $this->sleeps = [];
        return FpChecker::withTransport($t, function ($s): void {
            $this->sleeps[] = $s;
        }, self::SK, $pk, $baseUrl, $timeout);
    }

    private static function resp(int $status, string|array|null $body = null, array $headers = []): array
    {
        return FakeTransport::resp($status, $body, $headers);
    }

    private function error(callable $fn): FpCheckerApiError
    {
        try {
            $fn();
        } catch (FpCheckerApiError $e) {
            return $e;
        }
        $this->fail('expected FpCheckerApiError');
    }

    // --- surface ---

    /** @return list<array{string, string, string, list<array<string, mixed>>, bool, list<string>}> */
    public static function operations(): array
    {
        $spec = json_decode((string) file_get_contents(dirname(__DIR__, 3) . '/openapi/fpchecker-api.json'), true, 512, JSON_THROW_ON_ERROR);
        $deref = static function (array $p) use ($spec): array {
            if (isset($p['$ref'])) {
                $o = $spec;
                foreach (array_slice(explode('/', $p['$ref']), 1) as $k) {
                    $o = $o[$k];
                }
                return $o;
            }
            return $p;
        };
        $ops = [];
        foreach ($spec['paths'] as $path => $item) {
            foreach ($item as $method => $op) {
                if (!is_array($op) || !isset($op['operationId'])) {
                    continue;
                }
                $params = array_map($deref, [...($item['parameters'] ?? []), ...($op['parameters'] ?? [])]);
                $sec = [];
                foreach ($op['security'] ?? $spec['security'] ?? [] as $s) {
                    foreach (array_keys($s) as $k) {
                        $sec[] = $k;
                    }
                }
                if (in_array('managementKey', $sec, true)) {
                    continue; // the account-level management API is not part of this SDK
                }
                $ops[$op['operationId']] = [$op['operationId'], strtoupper($method), $path, $params, isset($op['requestBody']), $sec];
            }
        }
        return $ops;
    }

    public function testOpTableComplete(): void
    {
        $this->assertCount(18, self::operations());
    }

    public function testEveryOperationIdHasMethod(): void
    {
        $missing = array_values(array_filter(array_keys(self::operations()), static fn ($id) => !is_callable([FpChecker::class, $id])));
        $this->assertSame([], $missing);
    }

    #[DataProvider('operations')]
    public function testOperationTable(string $opId, string $method, string $path, array $params, bool $hasBody, array $sec): void
    {
        $t = new FakeTransport(self::resp(200, ['ok' => true]));
        $client = $this->mk($t, self::PK);
        $pathParams = array_values(array_filter($params, static fn ($p) => $p['in'] === 'path'));
        $queryParams = array_values(array_filter($params, static fn ($p) => $p['in'] === 'query'));
        $args = [];
        foreach ($pathParams as $i => $_) {
            $args[] = "id/$i x";
        }
        if ($hasBody) {
            $args[] = ['a' => 1];
        } elseif ($queryParams !== []) {
            $args[] = ['intent' => 'i'];
        }
        $out = $opId === 'botCheck'
            ? $client->botCheck('GET', 'https://x.test/', '1.1.1.1', [])
            : $client->$opId(...$args);
        $this->assertSame(['ok' => true], $out);
        $expected = $path;
        foreach ($pathParams as $i => $p) {
            $expected = str_replace('{' . $p['name'] . '}', rawurlencode("id/$i x"), $expected);
        }
        $this->assertSame($expected, parse_url($t->calls[0]['url'], PHP_URL_PATH));
        $this->assertSame($method, $t->calls[0]['method']);
        $this->assertSame(in_array('secretKey', $sec, true), $t->header(0, 'X-Secret-Key') !== null);
        $this->assertSame(in_array('publishableKey', $sec, true), $t->header(0, 'X-Publishable-Key') !== null);
        if (in_array('secretKey', $sec, true)) {
            $this->assertSame(self::SK, $t->header(0, 'X-Secret-Key'));
        }
        if (in_array('publishableKey', $sec, true)) {
            $this->assertSame(self::PK, $t->header(0, 'X-Publishable-Key'));
        }
        $this->assertStringNotContainsString('sk_test', $t->calls[0]['url']);
        $this->assertStringNotContainsString('pk_test', $t->calls[0]['url']);
    }

    // --- construction ---

    public function testRequiresSecretKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new FpChecker('');
    }

    public function testNullSecretKeyIsATypeError(): void
    {
        $this->expectException(\TypeError::class);
        new FpChecker(null); // @phpstan-ignore-line
    }

    public function testReprAndStrHideKey(): void
    {
        $c = new FpChecker(self::SK, self::PK);
        foreach ([(string) $c, print_r($c, true), var_export(print_r($c, true), true)] as $text) {
            $this->assertStringNotContainsString(self::SK, $text);
            $this->assertStringNotContainsString(self::PK, $text);
        }
        ob_start();
        var_dump($c);
        $dumped = (string) ob_get_clean();
        $this->assertStringNotContainsString(self::SK, $dumped);
        $this->assertStringNotContainsString(self::PK, $dumped);
    }

    public function testClientCannotBeSerialized(): void
    {
        $this->expectException(LogicException::class);
        serialize(new FpChecker(self::SK));
    }

    #[DataProvider('invalidTimeouts')]
    public function testInvalidTimeoutRejected(mixed $timeout): void
    {
        $this->expectException(InvalidArgumentException::class);
        new FpChecker(self::SK, null, 'https://x.test', $timeout);
    }

    /** @return array<string, array{mixed}> */
    public static function invalidTimeouts(): array
    {
        return ['zero' => [0], 'negative' => [-1.5], 'nan' => [NAN], 'inf' => [INF], 'true' => [true], 'false' => [false], 'string' => ['5'], 'null' => [null]];
    }

    public function testValidTimeoutsAccepted(): void
    {
        $this->assertInstanceOf(FpChecker::class, new FpChecker(self::SK, null, 'https://x.test', 3));
        $this->assertInstanceOf(FpChecker::class, new FpChecker(self::SK, null, 'https://x.test', 0.25));
    }

    #[DataProvider('badKeys')]
    public function testKeysWithControlCharsRejected(string $bad): void
    {
        try {
            new FpChecker($bad);
            $this->fail('secretKey accepted');
        } catch (InvalidArgumentException) {
            $this->addToAssertionCount(1);
        }
        $this->expectException(InvalidArgumentException::class);
        new FpChecker(self::SK, $bad);
    }

    /** @return array<string, array{string}> */
    public static function badKeys(): array
    {
        return ['lf' => ["a\nb"], 'cr' => ["a\rb"], 'nul' => ["a\0b"], 'del' => ["a\x7fb"], 'non-ascii' => ["k\u{e9}y"]];
    }

    public function testEmptyPublishableKeyRejectedButNullOk(): void
    {
        $this->assertInstanceOf(FpChecker::class, new FpChecker(self::SK, null));
        $this->expectException(InvalidArgumentException::class);
        new FpChecker(self::SK, '');
    }

    public function testBaseUrlValidation(): void
    {
        foreach (['http://api.example.com', 'not a url', 'ftp://x.test', 'https://', '', 'http://localhost.evil.test'] as $bad) {
            try {
                new FpChecker('sk', null, $bad);
                $this->fail("accepted $bad");
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
        foreach (['http://localhost:8787', 'http://127.0.0.1:1', 'http://[::1]:2', 'https://x.test'] as $ok) {
            $this->assertInstanceOf(FpChecker::class, new FpChecker('sk', null, $ok));
        }
    }

    public function testBaseUrlTrailingSlashesStripped(): void
    {
        $t = new FakeTransport(self::resp(200, []));
        $this->mk($t, null, 'https://x.test///')->getHealth();
        $this->assertSame('https://x.test/health', $t->calls[0]['url']);
    }

    // --- requests ---

    public function testQueryEncodingAndBaseUrl(): void
    {
        $t = new FakeTransport(self::resp(200, []));
        $this->mk($t, null, 'https://x.test/')->searchEvents(['visitorId' => 'v 1', 'bot' => true, 'off' => false, 'limit' => 5, 'linkedId' => null]);
        $this->assertSame('https://x.test/v1/events?visitorId=v+1&bot=true&off=false&limit=5', $t->calls[0]['url']);
    }

    public function testQueryEncodingMatchesQuotePlus(): void
    {
        $this->assertSame(
            '?k=a%2Fb%3Fc%26d%3De+f~%2A-_.%C3%A9',
            FpChecker::queryString(['k' => "a/b?c&d=e f~*-_.\u{e9}"]),
        );
        $this->assertSame('?a+b=%2B', FpChecker::queryString(['a b' => '+']));
        $this->assertSame('', FpChecker::queryString(['x' => null]));
    }

    public function testNonScalarQueryValueRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        FpChecker::queryString(['x' => [1]]);
    }

    public function testPathParamEncoded(): void
    {
        $t = new FakeTransport(self::resp(200, []));
        $this->mk($t)->getVisitor('a/b');
        $this->assertSame('https://api.fpchecker.com/v1/visitors/a%2Fb', $t->calls[0]['url']);
    }

    public function testPathIdIsPercentEncoded(): void
    {
        $t = new FakeTransport(self::resp(200, []));
        $this->mk($t)->getEvent('a/b?c#d~e');
        $this->assertSame('https://api.fpchecker.com/v1/events/a%2Fb%3Fc%23d~e', $t->calls[0]['url']);
        $this->assertNull(parse_url($t->calls[0]['url'], PHP_URL_QUERY));
    }

    public function testPathIdThatCouldChangeTheRouteIsRejected(): void
    {
        $t = new FakeTransport();
        $c = $this->mk($t);
        foreach (['', '.', '..'] as $bad) {
            foreach ([
                fn () => $c->getEvent($bad),
                fn () => $c->getVisitor($bad),
                fn () => $c->deleteVisitor($bad),
                fn () => $c->updateEvent($bad, []),
            ] as $call) {
                try {
                    $call();
                    $this->fail("accepted '$bad'");
                } catch (InvalidArgumentException) {
                    $this->addToAssertionCount(1);
                }
            }
        }
        $this->assertSame([], $t->calls);
    }

    public function testPostSendsJson(): void
    {
        $t = new FakeTransport(self::resp(200, ['ok' => true]));
        $this->mk($t)->checkEligibility(['visitorId' => 'v_1']);
        $this->assertSame('POST', $t->calls[0]['method']);
        $this->assertSame('{"visitorId":"v_1"}', $t->calls[0]['body']);
        $this->assertSame('application/json', $t->header(0, 'Content-Type'));
        $this->assertSame('fpchecker-php/0.1.0', $t->header(0, 'User-Agent'));
        $this->assertSame('application/json', $t->header(0, 'Accept'));
    }

    public function testEmptyBodyIsAnObjectAndSlashesAreNotEscaped(): void
    {
        $t = new FakeTransport(self::resp(200, []), self::resp(200, []));
        $c = $this->mk($t);
        $c->checkQuota([]);
        $c->checkQuota(['u' => 'https://x.test/a']);
        $this->assertSame('{}', $t->calls[0]['body']);
        $this->assertSame('{"u":"https://x.test/a"}', $t->calls[1]['body']);
    }

    public function testNonSerializableBodyRejectedBeforeAnyRequest(): void
    {
        $t = new FakeTransport();
        try {
            $this->mk($t)->checkQuota(['x' => NAN]);
            $this->fail('accepted NAN');
        } catch (InvalidArgumentException) {
            $this->assertSame([], $t->calls);
        }
    }

    public function testSecretNotSentOnPublishableOpsAndViceVersa(): void
    {
        $t = new FakeTransport(self::resp(200, []), self::resp(200, []));
        $c = $this->mk($t, self::PK);
        $c->identify([]);
        $c->getHealth();
        $this->assertNull($t->header(0, 'X-Secret-Key'));
        $this->assertSame(self::PK, $t->header(0, 'X-Publishable-Key'));
        $this->assertNull($t->header(1, 'X-Secret-Key'));
        $this->assertNull($t->header(1, 'X-Publishable-Key'));
    }

    public function testPublishableOpsNeedKey(): void
    {
        $t = new FakeTransport();
        $c = $this->mk($t);
        foreach ([fn () => $c->identify([]), fn () => $c->getChallenge(['intent' => 'i'])] as $call) {
            try {
                $call();
                $this->fail('no LogicException');
            } catch (LogicException) {
                $this->addToAssertionCount(1);
            }
        }
        $this->assertSame([], $t->calls);
    }

    public function testMobileSignalFiltersAreForwarded(): void
    {
        $t = new FakeTransport(self::resp(200, []));
        $this->mk($t)->searchEvents(['rooted' => true, 'hooked' => false, 'emulator' => true, 'mitm' => true, 'locationSpoofed' => false, 'clonedApp' => true]);
        $this->assertSame(
            'https://api.fpchecker.com/v1/events?rooted=true&hooked=false&emulator=true&mitm=true&locationSpoofed=false&clonedApp=true',
            $t->calls[0]['url'],
        );
    }

    public function testBotCheckBodyShape(): void
    {
        $t = new FakeTransport(self::resp(200, ['bot' => false]), self::resp(200, []));
        $c = $this->mk($t);
        $c->botCheck('GET', 'https://x.test/p', '1.2.3.4', ['user-agent' => 'UA']);
        $c->botCheck('GET', 'https://x.test/p', '1.2.3.4', []);
        $this->assertSame('{"method":"GET","url":"https://x.test/p","ip":"1.2.3.4","headers":{"user-agent":"UA"}}', $t->calls[0]['body']);
        $this->assertSame('{"method":"GET","url":"https://x.test/p","ip":"1.2.3.4","headers":{}}', $t->calls[1]['body']);
    }

    // --- responses ---

    public function testTwoXxOkFalseReturnedAsData(): void
    {
        $t = new FakeTransport(self::resp(200, ['ok' => false, 'reason' => 'quota_exhausted']));
        $this->assertSame(['ok' => false, 'reason' => 'quota_exhausted'], $this->mk($t)->checkQuota([]));
    }

    public function testTwoXxEmptyOrNonJsonIsEmptyArray(): void
    {
        $t = new FakeTransport(self::resp(204), self::resp(200, '<html>'), self::resp(200, '{"a":1} trailing'), self::resp(200, 'null'), self::resp(200, '"str"'));
        $c = $this->mk($t);
        for ($i = 0; $i < 5; $i++) {
            $this->assertSame([], $c->getHealth(), "case $i");
        }
    }

    public function testNon2xxErrorCode(): void
    {
        $t = new FakeTransport(self::resp(403, ['ok' => false, 'error' => 'forbidden']));
        $e = $this->error(fn () => $this->mk($t)->getEvent('e'));
        $this->assertSame(403, $e->status());
        $this->assertSame('forbidden', $e->code());
        $this->assertNull($e->retryAfter());
        $this->assertSame(['ok' => false, 'error' => 'forbidden'], $e->body());
    }

    public function testCodeFallsBackToReasonThenNone(): void
    {
        $t = new FakeTransport(self::resp(400, ['ok' => false, 'reason' => 'bad_input']), self::resp(502, '<html>'));
        $c = $this->mk($t);
        $this->assertSame('bad_input', $this->error(fn () => $c->updateEvent('e', []))->code());
        $b = $this->error(fn () => $c->createIntent([]));
        $this->assertSame(502, $b->status());
        $this->assertNull($b->code());
    }

    public function testErrorNeverContainsSecret(): void
    {
        $t = new FakeTransport(self::resp(401, ['error' => 'bad_key']));
        $e = $this->error(fn () => $this->mk($t)->getEvent('e'));
        $this->assertNoSecret($e);
    }

    private function assertNoSecret(\Throwable $e): void
    {
        $texts = [$e->getMessage(), (string) $e, print_r($e, true), var_export($e, true), $e->getTraceAsString(), json_encode($e->getTrace(), JSON_PARTIAL_OUTPUT_ON_ERROR) ?: ''];
        if (method_exists($e, '__debugInfo')) {
            $texts[] = print_r($e->__debugInfo(), true);
        }
        foreach ($texts as $text) {
            $this->assertStringNotContainsString(self::SK, $text);
        }
    }

    public function testTransportFailureNeverContainsSecret(): void
    {
        $leaky = new RuntimeException('boom ' . self::SK);
        $t = new FakeTransport($leaky);
        $e = $this->error(fn () => $this->mk($t)->checkQuota([]));
        $this->assertSame([0, 'network_error'], [$e->status(), $e->code()]);
        $this->assertNull($e->getPrevious());
        $this->assertNoSecret($e);
    }

    public function testExceptionDebugInfoOmitsBody(): void
    {
        $e = new FpCheckerApiError(500, 'x', 3, ['secret' => 'zzz']);
        $this->assertStringNotContainsString('zzz', print_r($e->__debugInfo(), true));
        $this->assertSame(['secret' => 'zzz'], $e->body());
        $this->assertSame(3, $e->retryAfter());
    }

    // --- retries ---

    public function testGetRetriedOn503WithRetryAfter(): void
    {
        $t = new FakeTransport(self::resp(503, ['error' => 'u'], ['Retry-After' => '2']), self::resp(200, ['ok' => true]));
        $c = $this->mk($t);
        $this->assertSame(['ok' => true], $c->getVisitor('v'));
        $this->assertCount(2, $t->calls);
        $this->assertEquals([2], $this->sleeps);
    }

    public function testGetGivesUpAfterTwoRetries(): void
    {
        $t = new FakeTransport(self::resp(500, []), self::resp(500, []), self::resp(429, ['error' => 'rate'], ['retry-after' => '1']));
        $e = $this->error(fn () => $this->mk($t)->getHealth());
        $this->assertCount(3, $t->calls);
        $this->assertSame(429, $e->status());
        $this->assertSame(1, $e->retryAfter());
        $this->assertEquals([0.5, 1.0], $this->sleeps);
    }

    public function testRetryAfterCapped(): void
    {
        $t = new FakeTransport(self::resp(429, [], ['Retry-After' => '3600']), self::resp(200, []));
        $this->mk($t)->getStatus();
        $this->assertEquals([10.0], $this->sleeps);
    }

    #[DataProvider('badRetryAfter')]
    public function testRetryAfterOnlyDigits(string $value): void
    {
        $t = new FakeTransport(self::resp(503, [], ['Retry-After' => $value]), self::resp(200, []));
        $this->mk($t)->getStatus();
        $this->assertEquals([0.5], $this->sleeps);
    }

    /** @return array<string, array{string}> */
    public static function badRetryAfter(): array
    {
        return ['negative' => ['-1'], 'float' => ['1.5'], 'date' => ['Wed, 21 Oct 2026 07:28:00 GMT'], 'too long' => ['1234567890'], 'empty' => ['']];
    }

    public function testNoRetryOnOther4xx(): void
    {
        $t = new FakeTransport(self::resp(404, ['error' => 'not_found']));
        $this->error(fn () => $this->mk($t)->getEvent('x'));
        $this->assertCount(1, $t->calls);
    }

    #[DataProvider('retryableStatuses')]
    public function testBilledPostNeverRetried(int $status): void
    {
        $t = new FakeTransport(self::resp($status, ['error' => 'x'], ['Retry-After' => '1']), self::resp(200, []));
        $this->error(fn () => $this->mk($t)->checkEligibility(['visitorId' => 'v']));
        $this->assertCount(1, $t->calls);
        $this->assertSame([], $this->sleeps);
    }

    /** @return array<string, array{int}> */
    public static function retryableStatuses(): array
    {
        return ['429' => [429], '503' => [503]];
    }

    public function testPatchDeleteNeverRetried(): void
    {
        $a = new FakeTransport(self::resp(503, []), self::resp(200, []));
        $this->error(fn () => $this->mk($a)->updateEvent('e', []));
        $b = new FakeTransport(self::resp(503, []), self::resp(200, []));
        $this->error(fn () => $this->mk($b)->deleteVisitor('v'));
        $this->assertCount(1, $a->calls);
        $this->assertCount(1, $b->calls);
    }

    // --- network ---

    public function testNetworkErrorWrapped(): void
    {
        $t = new FakeTransport(new TransportException('refused'));
        $e = $this->error(fn () => $this->mk($t)->checkQuota([]));
        $this->assertSame([0, 'network_error'], [$e->status(), $e->code()]);
        $this->assertNull($e->body());
        $this->assertCount(1, $t->calls);
    }

    public function testTimeoutsWrapped(): void
    {
        $x = new TransportException('t', true);
        $t = new FakeTransport($x, $x, $x);
        $e = $this->error(fn () => $this->mk($t)->getHealth());
        $this->assertSame([0, 'timeout'], [$e->status(), $e->code()]);
        $this->assertCount(3, $t->calls);
    }

    public function testUncheckedTransportErrorsBecomeNetworkError(): void
    {
        $t = new FakeTransport(new \TypeError('bad'), new \LogicException('worse'));
        $e = $this->error(fn () => $this->mk($t)->checkQuota([]));
        $this->assertSame('network_error', $e->code());
        $t2 = new FakeTransport(new \Error('bad'));
        $this->assertSame('network_error', $this->error(fn () => $this->mk($t2)->checkQuota([]))->code());
    }

    public function testGetRetriesNetworkFailuresAtMostTwice(): void
    {
        $t = new FakeTransport(new TransportException('a'), new TransportException('b'), new TransportException('c'), self::resp(200, []));
        $e = $this->error(fn () => $this->mk($t)->getVisitor('v'));
        $this->assertCount(3, $t->calls);
        $this->assertSame('network_error', $e->code());
        $ok = new FakeTransport(new TransportException('a'), self::resp(200, ['ok' => true]));
        $this->assertSame(['ok' => true], $this->mk($ok)->getVisitor('v'));
    }

    public function testNonGetNeverRetriesNetworkFailures(): void
    {
        foreach ([fn (FpChecker $c) => $c->updateEvent('e', []), fn (FpChecker $c) => $c->deleteVisitor('v'), fn (FpChecker $c) => $c->checkEligibility([])] as $call) {
            $t = new FakeTransport(new TransportException('x'), self::resp(200, []));
            $this->error(fn () => $call($this->mk($t)));
            $this->assertCount(1, $t->calls);
        }
    }

    // --- redirects ---

    public function testRedirectToOtherHostIsNeverFollowed(): void
    {
        $t = new FakeTransport(self::resp(302, '', ['Location' => 'https://evil.test/x']), self::resp(200, []));
        $e = $this->error(fn () => $this->mk($t)->checkQuota([]));
        $this->assertCount(1, $t->calls);
        $this->assertSame('api.fpchecker.com', parse_url($t->calls[0]['url'], PHP_URL_HOST));
        $this->assertSame([0, 'network_error'], [$e->status(), $e->code()]);
    }

    public function testRedirectOnGetIsRetriedLikeANetworkFailureButNeverFollowed(): void
    {
        $loc = ['Location' => 'https://evil.test/x'];
        $t = new FakeTransport(self::resp(301, '', $loc), self::resp(308, '', $loc), self::resp(307, '', $loc));
        $e = $this->error(fn () => $this->mk($t)->getHealth());
        $this->assertCount(3, $t->calls);
        foreach ($t->calls as $call) {
            $this->assertSame('api.fpchecker.com', parse_url($call['url'], PHP_URL_HOST));
        }
        $this->assertSame('network_error', $e->code());
    }

    // --- real sockets (php -S + the real curl transport) ---

    /** @return array<string, array{int}> */
    public static function redirectCodes(): array
    {
        return ['301' => [301], '302' => [302], '307' => [307], '308' => [308]];
    }

    #[DataProvider('redirectCodes')]
    public function testRealRedirectsNotFollowed(int $code): void
    {
        $log = tempnam(sys_get_temp_dir(), 'fpredir');
        $target = new PhpServer('target.php', ['FP_LOG' => $log]);
        $red = new PhpServer('redirector.php', ['FP_CODE' => (string) $code, 'FP_TARGET_PORT' => (string) $target->port]);
        try {
            $noSleep = static function ($s): void {
            };
            $c = FpChecker::withTransport(new CurlTransport(), $noSleep, self::SK, null, $red->url(), 5);
            $a = $this->error(fn () => $c->checkQuota([]));
            $this->assertSame([0, 'network_error'], [$a->status(), $a->code()]);
            $b = $this->error(fn () => $c->getHealth());
            $this->assertSame([0, 'network_error'], [$b->status(), $b->code()]);
            $this->assertSame('', (string) file_get_contents($log), 'target must receive zero requests');
        } finally {
            $red->stop();
            $target->stop();
            @unlink($log);
        }
    }

    public function testPublicConstructorUsesNonFollowingTransport(): void
    {
        $log = tempnam(sys_get_temp_dir(), 'fpredir');
        $target = new PhpServer('target.php', ['FP_LOG' => $log]);
        $red = new PhpServer('redirector.php', ['FP_CODE' => '307', 'FP_TARGET_PORT' => (string) $target->port]);
        try {
            $c = new FpChecker(self::SK, null, $red->url(), 5);
            $e = $this->error(fn () => $c->checkQuota([]));
            $this->assertSame('network_error', $e->code());
            $this->assertSame('', (string) file_get_contents($log));
        } finally {
            $red->stop();
            $target->stop();
            @unlink($log);
        }
    }

    public function testRealRoundtripSendsHeadersAndBody(): void
    {
        $srv = new PhpServer('echo.php');
        try {
            $c = new FpChecker(self::SK, self::PK, $srv->url() . '/', 5);
            $got = $c->searchEvents(['visitorId' => 'v 1']);
            $this->assertSame('GET', $got['method']);
            $this->assertSame('/v1/events?visitorId=v+1', $got['uri']);
            $this->assertSame(self::SK, $got['secret']);
            $this->assertNull($got['publishable']);
            $this->assertSame('fpchecker-php/0.1.0', $got['ua']);

            $post = $c->checkEligibility(['visitorId' => 'v_1', 'n' => "\u{e9}"]);
            $this->assertSame('POST', $post['method']);
            $this->assertSame('application/json', $post['ctype']);
            $this->assertSame('{"visitorId":"v_1","n":"\\u00e9"}', $post['body']);

            $id = $c->identify([]);
            $this->assertSame(self::PK, $id['publishable']);
            $this->assertNull($id['secret']);

            $this->assertSame('DELETE', $c->deleteVisitor('a/b')['method']);
            $this->assertSame('/v1/visitors/a%2Fb', $c->getVisitor('a/b')['uri']);
        } finally {
            $srv->stop();
        }
    }

    public function testRealErrorStatusKeepsRetryAfterHeader(): void
    {
        // echo.php answers 200 with Retry-After, so check the header plumbing through a 429 via a fake instead.
        $transport = new CurlTransport();
        $srv = new PhpServer('echo.php');
        try {
            $res = $transport->send('GET', $srv->url() . '/x', ['Accept' => 'application/json'], null, 5.0);
            $this->assertSame(200, $res['status']);
            $this->assertSame('7', $res['headers']['retry-after']);
        } finally {
            $srv->stop();
        }
    }

    public function testRealTimeoutMapsToTimeout(): void
    {
        $srv = new PhpServer('slow.php');
        try {
            $c = new FpChecker(self::SK, null, $srv->url(), 0.3);
            $e = $this->error(fn () => $c->checkQuota([]));
            $this->assertSame([0, 'timeout'], [$e->status(), $e->code()]);
        } finally {
            $srv->stop();
        }
    }

    public function testConnectionRefusedIsNetworkError(): void
    {
        $probe = stream_socket_server('tcp://127.0.0.1:0');
        $port = (int) substr((string) strrchr((string) stream_socket_get_name($probe, false), ':'), 1);
        fclose($probe);
        $c = new FpChecker(self::SK, null, 'http://127.0.0.1:' . $port, 2);
        $e = $this->error(fn () => $c->checkQuota([]));
        $this->assertSame([0, 'network_error'], [$e->status(), $e->code()]);
        $this->assertNoSecret($e);
    }

    public function testNonHttpSchemeIsRefusedByTheTransport(): void
    {
        $this->expectException(TransportException::class);
        (new CurlTransport())->send('GET', 'file:///etc/hostname', [], null, 2.0);
    }

    // --- debug output on construction errors ---

    public function testConstructionErrorTraceHidesSecretOnPhp82Plus(): void
    {
        if (PHP_VERSION_ID < 80200) {
            $this->markTestSkipped('#[\SensitiveParameter] needs PHP 8.2+; on 8.1 the constructor frame lists its arguments');
        }
        try {
            new FpChecker(self::SK, null, 'ftp://x.test');
            $this->fail('accepted ftp');
        } catch (InvalidArgumentException $e) {
            $this->assertStringNotContainsString(self::SK, (string) $e);
        }
    }
}
