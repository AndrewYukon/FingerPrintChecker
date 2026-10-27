<?php

declare(strict_types=1);

namespace FpChecker\Tests;

use FpChecker\Webhook;
use FpChecker\WebhookSignatureError;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class WebhookTest extends TestCase
{
    /** @return array<string, mixed> */
    private static function vectors(): array
    {
        return json_decode((string) file_get_contents(__DIR__ . '/../../../test-vectors/webhook-signature.json'), true, 512, JSON_THROW_ON_ERROR);
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

    private static function secret(): string
    {
        return self::vectors()['secret'];
    }

    private static function sign(string $body, int $t, ?string $secret = null): string
    {
        return 't=' . $t . ',v1=' . hash_hmac('sha256', $t . '.' . $body, $secret ?? self::secret());
    }

    private function code(callable $fn): string
    {
        try {
            $fn();
        } catch (WebhookSignatureError $e) {
            return $e->code();
        }
        $this->fail('expected WebhookSignatureError');
    }

    public function testVectorCountIsNotFiltered(): void
    {
        $this->assertCount(17, self::vectors()['cases']);
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('cases')]
    public function testWebhookVector(array $case): void
    {
        $call = fn () => Webhook::verifyWebhookSignature($case['body'], $case['header'], self::secret(), 300, $case['now']);
        if ($case['expect'] === true) {
            $call();
            $this->addToAssertionCount(1);
        } else {
            $this->assertSame($case['expect']['error'], $this->code($call));
        }
    }

    public function testDefaultNowAndFloatClock(): void
    {
        $body = '{"a":"é"}';
        Webhook::verifyWebhookSignature($body, self::sign($body, time()), self::secret());
        Webhook::verifyWebhookSignature($body, self::sign($body, 1000), self::secret(), 300, 1000.5);
        $this->addToAssertionCount(2);
    }

    /** @return array<string, array{int|float}> */
    public static function badTolerances(): array
    {
        return ['nan' => [NAN], 'inf' => [INF], '-inf' => [-INF], '-1' => [-1], '-0.5' => [-0.5]];
    }

    #[DataProvider('badTolerances')]
    public function testToleranceMustBeFiniteNonNegative(int|float $tol): void
    {
        $this->expectException(InvalidArgumentException::class);
        Webhook::verifyWebhookSignature('{}', self::sign('{}', 1000), self::secret(), $tol, 1000);
    }

    public function testToleranceMustBeANumber(): void
    {
        $this->expectException(\TypeError::class);
        Webhook::verifyWebhookSignature('{}', self::sign('{}', 1000), self::secret(), '300', 1000); // @phpstan-ignore-line
    }

    public function testNonFiniteNowIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Webhook::verifyWebhookSignature('{}', self::sign('{}', 1000), self::secret(), 300, NAN);
    }

    public function testToleranceZeroAndFloat(): void
    {
        $sig = self::sign('{}', 1000);
        Webhook::verifyWebhookSignature('{}', $sig, self::secret(), 0, 1000);
        $this->assertSame('expired', $this->code(fn () => Webhook::verifyWebhookSignature('{}', $sig, self::secret(), 0, 1001)));
        $this->assertSame('future', $this->code(fn () => Webhook::verifyWebhookSignature('{}', $sig, self::secret(), 0, 999)));
        Webhook::verifyWebhookSignature('{}', $sig, self::secret(), 1.5, 1001);
        $this->addToAssertionCount(2);
    }

    public function testNonStringHeaderIsATypeError(): void
    {
        $this->expectException(\TypeError::class);
        Webhook::verifyWebhookSignature('{}', null, self::secret(), 300, 1); // @phpstan-ignore-line
    }

    public function testNonAsciiDigitsInTAreMalformed(): void
    {
        $this->assertSame('malformed_header', $this->code(fn () => Webhook::verifyWebhookSignature('{}', 't=١٢,v1=' . str_repeat('0', 64), self::secret(), 300, 1)));
        $this->assertSame('malformed_header', $this->code(fn () => Webhook::verifyWebhookSignature('{}', "t=1\n,v1=" . str_repeat('0', 64), self::secret(), 300, 1)));
        $this->assertSame('malformed_header', $this->code(fn () => Webhook::verifyWebhookSignature('{}', '', self::secret(), 300, 1)));
    }

    public function testValidSignatureOutsideToleranceIsRejected(): void
    {
        $body = '{"x":1}';
        $sig = self::sign($body, 1000);
        $this->assertSame('expired', $this->code(fn () => Webhook::verifyWebhookSignature($body, $sig, self::secret(), 300, 1301)));
        $this->assertSame('future', $this->code(fn () => Webhook::verifyWebhookSignature($body, $sig, self::secret(), 300, 699)));
        Webhook::verifyWebhookSignature($body, $sig, self::secret(), 300, 1300);
        $this->addToAssertionCount(1);
    }

    public function testV0OnlySchemeIsRejected(): void
    {
        $mac = hash_hmac('sha256', '1000.{}', self::secret());
        $this->assertSame('malformed_header', $this->code(fn () => Webhook::verifyWebhookSignature('{}', 't=1000,v0=' . $mac, self::secret(), 300, 1000)));
        // v0 alongside a bad v1 never rescues the request
        $this->assertSame('bad_signature', $this->code(fn () => Webhook::verifyWebhookSignature('{}', 't=1000,v0=' . $mac . ',v1=' . str_repeat('0', 64), self::secret(), 300, 1000)));
    }

    public function testAnyValidV1AmongSeveralPassesAndUppercaseHexIsAccepted(): void
    {
        $mac = hash_hmac('sha256', '1000.{}', self::secret());
        Webhook::verifyWebhookSignature('{}', 't=1000,v1=' . str_repeat('0', 64) . ',v1=' . strtoupper($mac), self::secret(), 300, 1000);
        $this->addToAssertionCount(1);
    }

    public function testBodyIsByteExact(): void
    {
        $sig = self::sign("{\"a\": 1}", 5);
        Webhook::verifyWebhookSignature("{\"a\": 1}", $sig, self::secret(), 300, 5);
        $this->assertSame('bad_signature', $this->code(fn () => Webhook::verifyWebhookSignature('{"a":1}', $sig, self::secret(), 300, 5)));
        $this->assertSame('bad_signature', $this->code(fn () => Webhook::verifyWebhookSignature("{\"a\": 1}", $sig, 'other', 300, 5)));
    }

    public function testInvalidUtf8BodyBytesAreSigned(): void
    {
        $body = "a\xffb";
        Webhook::verifyWebhookSignature($body, self::sign($body, 7), self::secret(), 300, 7);
        $this->addToAssertionCount(1);
    }

    public function testTraceCarriesNoSecret(): void
    {
        $prev = ini_set('zend.exception_ignore_args', '0');
        try {
            try {
                Webhook::verifyWebhookSignature('{}', self::sign('{}', 1000, 'other'), self::secret(), 300, 1000);
                $this->fail('accepted');
            } catch (WebhookSignatureError $e) {
                $trace = $e->getTrace();
                foreach ([json_encode($trace), var_export($trace, true), $e->getTraceAsString()] as $dump) {
                    $this->assertStringNotContainsString(self::secret(), (string) $dump);
                }
            }
        } finally {
            ini_set('zend.exception_ignore_args', $prev === false ? '1' : $prev);
        }
    }
}
