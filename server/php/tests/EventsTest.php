<?php

declare(strict_types=1);

namespace FpChecker\Tests;

use FpChecker\Events;
use FpChecker\Webhook;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class EventsTest extends TestCase
{
    /** @return array<string, mixed> */
    private static function vectors(): array
    {
        return json_decode((string) file_get_contents(__DIR__ . '/../../../test-vectors/webhook-signature.json'), true, 512, JSON_THROW_ON_ERROR);
    }

    /** @return array<string, mixed> */
    private static function vector(string $name): array
    {
        foreach (self::vectors()['cases'] as $c) {
            if ($c['name'] === $name) {
                return $c;
            }
        }
        throw new \LogicException('no vector ' . $name);
    }

    /** @param array<string, mixed> $data */
    private static function ev(array $data): string
    {
        return json_encode(['id' => 'evt_1', 'type' => 'identify', 'data' => ['visitorId' => 'v_1'] + $data], JSON_THROW_ON_ERROR);
    }

    /** @param array<string, mixed> $signals */
    private static function sig(array $signals): string
    {
        return self::ev(['signals' => $signals]);
    }

    public function testOkRuleActionVectorVerifiesAndParses(): void
    {
        $c = self::vector('ok_rule_action');
        Webhook::verifyWebhookSignature($c['body'], $c['header'], self::vectors()['secret'], 300, $c['now']);
        $e = Events::parseWebhookEvent($c['body']);
        $this->assertTrue($e->proxied);
        $ra = $e->ruleAction;
        $this->assertNotNull($ra);
        $this->assertSame(['deny', 'r_0a1b2c3d', 'Block hosting', 3], [$ra->type, $ra->ruleId, $ra->ruleName, $ra->rulesetVersion]);
    }

    /** @return array<string, array{string}> */
    public static function ruleTypes(): array
    {
        return ['allow' => ['allow'], 'human_check' => ['human_check'], 'deny' => ['deny'], 'none' => ['none']];
    }

    #[DataProvider('ruleTypes')]
    public function testRuleActionTypes(string $t): void
    {
        $e = Events::parseWebhookEvent(self::ev(['ruleAction' => ['type' => $t, 'rulesetVersion' => 1], 'proxied' => false]));
        $this->assertSame($t, $e->ruleAction?->type);
        $this->assertNull($e->ruleAction->ruleId);
        $this->assertFalse($e->proxied);
    }

    public function testNullAndMissingRuleAction(): void
    {
        $n = Events::parseWebhookEvent(self::ev(['ruleAction' => null]));
        $this->assertNull($n->ruleAction);
        $this->assertTrue($n->ruleActionPresent);
        $old = Events::parseWebhookEvent(self::ev([]));
        $this->assertNull($old->ruleAction);
        $this->assertFalse($old->ruleActionPresent);
        $this->assertNull($old->proxied);
    }

    public function testUnknownRuleTypeDoesNotThrow(): void
    {
        $this->assertSame('captcha', Events::parseWebhookEvent(self::ev(['ruleAction' => ['type' => 'captcha', 'rulesetVersion' => 2]]))->ruleAction?->type);
    }

    public function testRejectsNonEvents(): void
    {
        foreach (['{"a":1}', '[]', '[1]', 'not json', '', '{"data":[1]}', '{"data":{"visitorId":5}}'] as $body) {
            try {
                Events::parseWebhookEvent($body);
                $this->fail('accepted ' . $body);
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testEligibilityRuleId(): void
    {
        $a = Events::parseEligibilityAnswer(['ok' => true, 'eligible' => false, 'action' => 'deny', 'reason' => 'rule_deny', 'ruleId' => 'r_1']);
        $this->assertSame(['r_1', 'rule_deny', false, true], [$a->ruleId, $a->reason, $a->eligible, $a->ok]);
        $this->assertNull(Events::parseEligibilityAnswer(['ok' => true, 'eligible' => true, 'reason' => 'brand_new'])->ruleId);
    }

    public function testEligibilityOkIsStrictAndRejectsNonObjects(): void
    {
        $this->assertFalse(Events::parseEligibilityAnswer(['ok' => 'yes'])->ok);
        $this->assertNull(Events::parseEligibilityAnswer(['eligible' => 1])->eligible);
        foreach ([null, 'x', 5, [1, 2]] as $bad) {
            try {
                Events::parseEligibilityAnswer($bad);
                $this->fail('accepted');
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testOkMobileSignalsVectorVerifiesAndParses(): void
    {
        $c = self::vector('ok_mobile_signals');
        Webhook::verifyWebhookSignature($c['body'], $c['header'], self::vectors()['secret'], 300, $c['now']);
        $e = Events::parseWebhookEvent($c['body']);
        $m = $e->mobile;
        $this->assertNotNull($m);
        $this->assertSame([true, false, true, true, null, null], [$m->rooted, $m->hooked, $m->developerMode, $m->vpn, $m->locationSpoofed, $m->factoryResetAt]);
        $this->assertContains('os_vpn', $e->vpnMethods);
    }

    public function testOldPayloadNewFieldsAreNull(): void
    {
        $m = Events::parseWebhookEvent(self::sig(['mobile' => ['emulator' => false, 'attested' => true, 'integrity' => 'strong']]))->mobile;
        $this->assertNotNull($m);
        $this->assertNull($m->rooted);
        $this->assertNull($m->clonedApp);
        $this->assertNull($m->factoryResetAt);
        $this->assertSame('strong', $m->integrity);
        $this->assertNull(Events::parseWebhookEvent(self::sig(['mobile' => null]))->mobile);
        $e = Events::parseWebhookEvent(self::ev([]));
        $this->assertNull($e->mobile);
        $this->assertSame([], $e->vpnMethods);
    }

    public function testNonBooleanReadsAsNullAndUnknownVpnMethodKept(): void
    {
        $e = Events::parseWebhookEvent(self::sig([
            'vpn' => ['result' => true, 'methods' => ['os_vpn', 'future', 5]],
            'mobile' => ['rooted' => 'yes', 'factoryResetAt' => 5, 'integrity' => 'weird'],
        ]));
        $this->assertNull($e->mobile?->rooted);
        $this->assertNull($e->mobile->factoryResetAt);
        $this->assertNull($e->mobile->integrity);
        $this->assertSame(['os_vpn', 'future'], $e->vpnMethods);
    }

    public function testV1EventParsesWithoutInfo(): void
    {
        $e = Events::parseWebhookEvent(self::sig(['version' => 1, 'bot' => ['result' => 'bad', 'types' => ['webdriver']]]));
        $this->assertSame(1, $e->signalsVersion);
        $this->assertSame(['bad', ['webdriver'], null], [$e->bot?->result, $e->bot->types, $e->bot->info]);
    }

    public function testV2EventParsesGoodAndInfo(): void
    {
        $info = ['id' => 'googlebot', 'name' => 'Googlebot', 'provider' => 'Google', 'category' => 'search_crawler', 'identity' => 'verified'];
        $e = Events::parseWebhookEvent(self::sig(['version' => 2, 'bot' => ['result' => 'good', 'types' => [], 'info' => $info]]));
        $this->assertSame(2, $e->signalsVersion);
        $this->assertSame('good', $e->bot?->result);
        $this->assertSame(['googlebot', 'search_crawler', 'verified'], [$e->bot->info?->id, $e->bot->info->category, $e->bot->info->identity]);
        $none = Events::parseWebhookEvent(self::sig(['version' => 2, 'bot' => ['result' => 'not_detected', 'types' => [], 'info' => null]]));
        $this->assertNull($none->bot?->info);
    }

    public function testBotInfoDefaultsForMissingOrEmptyFields(): void
    {
        $e = Events::parseWebhookEvent(self::sig(['bot' => ['result' => 'good', 'info' => ['id' => 'x', 'category' => '']]]));
        $info = $e->bot?->info;
        $this->assertSame(['x', '', '', 'other', 'unknown'], [$info?->id, $info->name, $info->provider, $info->category, $info->identity]);
    }

    public function testSignalsVersionOnlyOneOrTwo(): void
    {
        foreach ([3, 0, '1', true, null] as $v) {
            $this->assertNull(Events::parseWebhookEvent(self::sig(['version' => $v]))->signalsVersion);
        }
    }

    public function testFloatSignalsVersionIsNotAVersion(): void
    {
        $e = Events::parseWebhookEvent('{"data":{"visitorId":"v","signals":{"version":1.0}}}');
        $this->assertNull($e->signalsVersion);
    }

    public function testEventWithoutSignalsHasNoBot(): void
    {
        $e = Events::parseWebhookEvent('{"data":{"visitorId":"v_1"}}');
        $this->assertNull($e->bot);
        $this->assertNull($e->signalsVersion);
    }

    public function testRawKeepsTheDecodedBodyAndObjectsAreReadonly(): void
    {
        $e = Events::parseWebhookEvent(self::ev([]));
        $this->assertSame('evt_1', $e->raw['id']);
        $this->expectException(\Error::class);
        $e->visitorId = 'other'; // @phpstan-ignore-line
    }
}
