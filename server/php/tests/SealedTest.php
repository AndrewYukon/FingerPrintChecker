<?php

declare(strict_types=1);

namespace FpChecker\Tests;

use FpChecker\Sealed;
use FpChecker\SealedResultError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SealedTest extends TestCase
{
    /** @return array<string, mixed> */
    private static function vectors(): array
    {
        return json_decode((string) file_get_contents(__DIR__ . '/../../../test-vectors/sealed-result-v1.json'), true, 512, JSON_THROW_ON_ERROR);
    }

    /** @return array<string, array{array<string, mixed>}> */
    public static function cases(): array
    {
        $out = [];
        foreach (self::vectors()['cases'] as $c) {
            $out[$c['name']] = [$c];
        }
        return $out;
    }

    private static function key(string $name): string
    {
        return self::vectors()['keys'][$name];
    }

    private function code(callable $fn): string
    {
        try {
            $fn();
        } catch (SealedResultError $e) {
            return $e->code();
        }
        $this->fail('expected SealedResultError');
    }

    public function testVectorCountIsNotFiltered(): void
    {
        $this->assertCount(17, self::vectors()['cases']);
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('cases')]
    public function testSealedVector(array $case): void
    {
        $keys = array_map(fn (string $k): string => self::key($k), $case['keys']);
        $expect = $case['expect'];
        if (isset($expect['error'])) {
            $this->assertSame($expect['error'], $this->code(fn () => Sealed::unsealResult($case['blob'], $keys)));
        } else {
            $this->assertEquals($expect, Sealed::unsealResult($case['blob'], $keys));
        }
    }

    public function testErrorCodesCoveredByVectors(): void
    {
        $codes = [];
        foreach (self::vectors()['cases'] as $c) {
            if (isset($c['expect']['error'])) {
                $codes[$c['expect']['error']] = true;
            }
        }
        $codes = array_keys($codes);
        sort($codes);
        $this->assertSame(['bad_format', 'decrypt_failed', 'invalid_key', 'unknown_key', 'unsupported_version'], $codes);
    }

    public function testInvalidKeyCheckedBeforeBlob(): void
    {
        $this->assertSame('invalid_key', $this->code(fn () => Sealed::unsealResult('!!!', [self::key('short')])));
    }

    /** @return array<string, array{mixed}> */
    public static function badKeys(): array
    {
        return ['null' => [null], 'string' => ['abc'], 'null entry' => [[null]], 'int entry' => [[123]], 'not base64' => [['not base64!']]];
    }

    #[DataProvider('badKeys')]
    public function testNonIterableOrBadKeys(mixed $keys): void
    {
        $blob = self::vectors()['cases'][0]['blob'];
        $this->assertSame('invalid_key', $this->code(fn () => Sealed::unsealResult($blob, $keys)));
    }

    public function testKeysMayBeAnyIterable(): void
    {
        $c = self::vectors()['cases'][0];
        $gen = (static function (string $k) {
            yield $k;
        })(self::key('a'));
        $this->assertEquals($c['expect'], Sealed::unsealResult($c['blob'], $gen));
    }

    /** @return array<string, array{mixed}> */
    public static function badBlobs(): array
    {
        return ['null' => [null], 'int' => [123], 'array' => [['abc']], 'empty' => ['']];
    }

    #[DataProvider('badBlobs')]
    public function testNonStringBlobIsBadFormat(mixed $blob): void
    {
        $this->assertSame('bad_format', $this->code(fn () => Sealed::unsealResult($blob, [self::key('a')])));
    }

    public function testNonAsciiDigitsAreNotBase64(): void
    {
        $this->assertSame('bad_format', $this->code(fn () => Sealed::unsealResult(str_repeat('Ａ', 16), [self::key('a')])));
        $this->assertSame('bad_format', $this->code(fn () => Sealed::unsealResult(self::vectors()['cases'][0]['blob'] . "\n", [self::key('a')])));
    }

    public function testErrorMessageHasNoKeyMaterial(): void
    {
        try {
            Sealed::unsealResult(self::vectors()['cases'][0]['blob'], [self::key('b')]);
            $this->fail('accepted');
        } catch (SealedResultError $e) {
            $this->assertStringNotContainsString(self::key('b'), (string) $e);
            $this->assertStringNotContainsString((string) base64_decode(self::key('b')), (string) $e);
        }
    }

    private static function seal(string $payload, ?string $keyB64 = null): string
    {
        $key = (string) base64_decode($keyB64 ?? self::key('a'));
        $head = 'fps1' . substr(hash('sha256', $key, true), 0, 4);
        $nonce = random_bytes(12);
        $ct = openssl_encrypt($payload, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $head);
        return base64_encode($head . $nonce . $ct . $tag);
    }

    /** @return array<string, array{string}> */
    public static function jsonEdgeCases(): array
    {
        return [
            'nan' => ['{"version":NaN}'],
            'inf' => ['{"version":1,"x":Infinity}'],
            'neg_inf' => ['{"version":1,"x":-Infinity}'],
            'deep' => [str_repeat('[', 100000) . str_repeat(']', 100000)],
            'deep_object' => ['{"version":1,"x":' . str_repeat('[', 600) . str_repeat(']', 600) . '}'],
            'bad_utf8' => ["\xff\xfe"],
            'empty' => [''],
            'bad_utf8_in_string' => ["{\"version\":1,\"x\":\"\xff\"}"],
            'array_not_object' => ['[{"version":1}]'],
            'empty_array' => ['[]'],
            'scalar' => ['1'],
        ];
    }

    #[DataProvider('jsonEdgeCases')]
    public function testJsonEdgeCasesAreDecryptFailed(string $payload): void
    {
        $this->assertSame('decrypt_failed', $this->code(fn () => Sealed::unsealResult(self::seal($payload), [self::key('a')])));
    }

    public function testVersionMustBeOne(): void
    {
        foreach (['{"x":1}', '{"version":2}', '{"version":"1"}', '{"version":true}', '{"version":null}'] as $p) {
            $this->assertSame('unsupported_version', $this->code(fn () => Sealed::unsealResult(self::seal($p), [self::key('a')])), $p);
        }
    }

    public function testSealHelperPositiveControl(): void
    {
        $this->assertSame(['version' => 1, 'x' => 2], Sealed::unsealResult(self::seal('{"version":1,"x":2}'), [self::key('a')]));
    }

    public function testTraceCarriesNoKeyMaterial(): void
    {
        $prev = ini_set('zend.exception_ignore_args', '0');
        try {
            $keyText = self::key('b');
            $keyBytes = (string) base64_decode($keyText);
            foreach ([
                fn () => Sealed::unsealResult(self::vectors()['cases'][0]['blob'], [$keyText]), // unknown_key
                fn () => Sealed::unsealResult('x', [$keyText, 'not base64!']), // invalid_key
            ] as $call) {
                try {
                    $call();
                    $this->fail('accepted');
                } catch (SealedResultError $e) {
                    $trace = $e->getTrace();
                    foreach ([json_encode($trace, JSON_INVALID_UTF8_SUBSTITUTE), var_export($trace, true), $e->getTraceAsString()] as $dump) {
                        $this->assertStringNotContainsString($keyText, (string) $dump);
                        $this->assertStringNotContainsString($keyBytes, (string) $dump);
                        $this->assertStringNotContainsString(bin2hex($keyBytes), (string) $dump);
                    }
                }
            }
        } finally {
            ini_set('zend.exception_ignore_args', $prev === false ? '1' : $prev);
        }
    }
}
