<?php

declare(strict_types=1);

namespace FpChecker\Tests;

use FpChecker\BotHeaders;
use FpChecker\FpChecker;
use PHPUnit\Framework\TestCase;

final class BotHeadersTest extends TestCase
{
    private const SIG_INPUT = 'sig1=("@authority" "content-type" "X-Custom" "cookie" "signature-agent");created=1;keyid="k";tag="web-bot-auth"';

    public function testKeepsAllowedSetAndDropsCookieAuthorization(): void
    {
        $allowed = [
            'User-Agent' => 'UA', 'Accept' => 'text/html', 'Accept-Language' => 'en', 'Accept-Encoding' => 'gzip',
            'Sec-CH-UA' => '"x"', 'Sec-CH-UA-Mobile' => '?0', 'Sec-CH-UA-Platform' => '"macOS"',
            'Sec-Fetch-Site' => 'none', 'Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'document', 'Sec-Fetch-User' => '?1',
            'Signature' => 'sig1=:a:', 'Signature-Input' => 'sig1=()', 'Signature-Agent' => '"https://chatgpt.com"',
            'Upgrade-Insecure-Requests' => '1',
        ];
        $out = BotHeaders::filter($allowed + ['Cookie' => 'sid=1', 'Authorization' => 'Bearer x', 'X-Forwarded-For' => '1.1.1.1']);
        $this->assertSame(array_change_key_case($allowed, CASE_LOWER), $out);
        $this->assertCount(15, BotHeaders::BOT_CHECK_HEADERS);
    }

    public function testRepeatedNamesAndListValuesAreJoined(): void
    {
        $this->assertSame(['accept' => 'a, b'], BotHeaders::filter(['Accept' => 'a', 'accept' => 'b', 'Cookie' => 'c']));
        $this->assertSame(['accept' => 'a, b'], BotHeaders::filter(['Accept' => ['a', 'b']]));
        $this->assertSame([], BotHeaders::filter(['Accept' => null]));
    }

    public function testKeepsSignatureInputCoveredComponents(): void
    {
        $out = BotHeaders::filter([
            'Signature-Input' => self::SIG_INPUT, 'Signature-Agent' => '"https://chatgpt.com"', 'Content-Type' => 'text/plain',
            'X-Custom' => 'v', 'X-Other' => 'no', 'Cookie' => 'sid=1', 'Authorization' => 'x',
        ]);
        $this->assertSame('text/plain', $out['content-type']);
        $this->assertSame('v', $out['x-custom']);
        $this->assertArrayNotHasKey('x-other', $out);
        $this->assertArrayNotHasKey('cookie', $out);
        $this->assertArrayNotHasKey('authorization', $out);
    }

    public function testNeverForwardsCredentialsEvenWhenCovered(): void
    {
        $out = BotHeaders::filter([
            'Signature-Input' => 'sig1=("cookie" "authorization" "proxy-authorization")', 'Cookie' => 'a', 'Authorization' => 'b', 'Proxy-Authorization' => 'c',
        ]);
        $this->assertSame(['signature-input'], array_keys($out));
    }

    public function testNoExtrasWithoutSignatureInput(): void
    {
        $this->assertSame(['user-agent' => 'u'], BotHeaders::filter(['content-type' => 'x', 'user-agent' => 'u']));
    }

    public function testCoveredExtrasAreCapped(): void
    {
        $names = array_map(static fn (int $i): string => 'x-h' . $i, range(1, 40));
        $input = 'sig1=(' . implode(' ', array_map(static fn (string $n): string => '"' . $n . '"', $names)) . ')';
        $headers = ['signature-input' => $input];
        foreach ($names as $n) {
            $headers[$n] = '1';
        }
        $this->assertCount(33, BotHeaders::filter($headers)); // 32 extras + signature-input
    }

    public function testBotCheckAppliesTheFilterItself(): void
    {
        $t = new FakeTransport(FakeTransport::resp(200, ['bot' => ['result' => 'not_detected']]));
        $c = FpChecker::withTransport($t, static function ($s): void {
        }, 'sk_test_123', null, 'https://api.fpchecker.com', 10.0);
        $c->botCheck('GET', 'https://shop.example/', '1.2.3.4', ['User-Agent' => 'UA', 'Cookie' => 'sid=1', 'Authorization' => 'Bearer x']);
        $sent = json_decode((string) $t->calls[0]['body'], true, 512, JSON_THROW_ON_ERROR);
        $this->assertSame(['user-agent' => 'UA'], $sent['headers']);
        $this->assertStringNotContainsString('sid=1', (string) $t->calls[0]['body']);
    }
}
