<?php

declare(strict_types=1);

namespace FpChecker;

use FpChecker\Events\BotInfo;
use FpChecker\Events\BotSignals;
use FpChecker\Events\EligibilityAnswer;
use FpChecker\Events\MobileSignals;
use FpChecker\Events\RuleAction;
use FpChecker\Events\WebhookEvent;
use InvalidArgumentException;
use JsonException;

/**
 * Typed views of webhook events and eligibility answers. Reasons and rule types are open strings: the server
 * may add values, and an unknown one never throws.
 */
final class Events
{
    private function __construct()
    {
    }

    /**
     * Parse a webhook body (verify its signature first).
     *
     * @throws InvalidArgumentException when the body is not JSON or not a webhook event
     */
    public static function parseWebhookEvent(string $rawBody): WebhookEvent
    {
        try {
            $body = json_decode($rawBody, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new InvalidArgumentException('parseWebhookEvent: not JSON');
        }
        $data = is_array($body) ? ($body['data'] ?? null) : null;
        if (!self::isObject($data) || !is_string($data['visitorId'] ?? null)) {
            throw new InvalidArgumentException('parseWebhookEvent: not a webhook event');
        }
        $signals = self::isObject($data['signals'] ?? null) ? $data['signals'] : [];
        $version = $signals['version'] ?? null;
        return new WebhookEvent(
            visitorId: $data['visitorId'],
            proxied: self::tri($data['proxied'] ?? null),
            ruleAction: self::parseRuleAction($data['ruleAction'] ?? null),
            ruleActionPresent: array_key_exists('ruleAction', $data),
            mobile: self::parseMobile($signals['mobile'] ?? null),
            vpnMethods: self::parseVpnMethods($signals['vpn'] ?? null),
            raw: $body,
            signalsVersion: $version === 1 || $version === 2 ? $version : null,
            bot: self::parseBot($signals['bot'] ?? null),
        );
    }

    /**
     * Narrow a `checkEligibility` response; `ruleId` is surfaced when present.
     *
     * @throws InvalidArgumentException when `$body` is not a JSON object
     */
    public static function parseEligibilityAnswer(mixed $body): EligibilityAnswer
    {
        if (!is_array($body) || ($body !== [] && array_is_list($body))) {
            throw new InvalidArgumentException('parseEligibilityAnswer: not an object');
        }
        return new EligibilityAnswer(
            ok: ($body['ok'] ?? null) === true,
            eligible: self::tri($body['eligible'] ?? null),
            action: self::optStr($body['action'] ?? null),
            reason: self::optStr($body['reason'] ?? null),
            ruleId: self::optStr($body['ruleId'] ?? null),
            raw: $body,
        );
    }

    /** A decoded JSON object (an empty `{}` and `[]` both decode to `[]`; the empty case is harmless here). */
    private static function isObject(mixed $v): bool
    {
        return is_array($v) && ($v === [] || !array_is_list($v));
    }

    private static function optStr(mixed $v): ?string
    {
        return is_string($v) ? $v : null;
    }

    private static function tri(mixed $v): ?bool
    {
        return is_bool($v) ? $v : null;
    }

    private static function parseRuleAction(mixed $v): ?RuleAction
    {
        if (!self::isObject($v) || !is_string($v['type'] ?? null)) {
            return null;
        }
        $version = $v['rulesetVersion'] ?? null;
        return new RuleAction(
            type: $v['type'],
            ruleId: self::optStr($v['ruleId'] ?? null),
            ruleName: self::optStr($v['ruleName'] ?? null),
            rulesetVersion: is_int($version) ? $version : 0,
        );
    }

    private static function parseMobile(mixed $v): ?MobileSignals
    {
        if (!self::isObject($v)) {
            return null;
        }
        $integrity = $v['integrity'] ?? null;
        return new MobileSignals(
            emulator: self::tri($v['emulator'] ?? null),
            attested: self::tri($v['attested'] ?? null),
            integrity: in_array($integrity, ['strong', 'basic', 'failed'], true) ? $integrity : null,
            rooted: self::tri($v['rooted'] ?? null),
            hooked: self::tri($v['hooked'] ?? null),
            debugger: self::tri($v['debugger'] ?? null),
            developerMode: self::tri($v['developerMode'] ?? null),
            mitm: self::tri($v['mitm'] ?? null),
            vpn: self::tri($v['vpn'] ?? null),
            locationSpoofed: self::tri($v['locationSpoofed'] ?? null),
            clonedApp: self::tri($v['clonedApp'] ?? null),
            factoryResetAt: self::optStr($v['factoryResetAt'] ?? null),
        );
    }

    /** @return list<string> */
    private static function strings(mixed $v): array
    {
        return is_array($v) && array_is_list($v)
            ? array_values(array_filter($v, 'is_string'))
            : [];
    }

    /** @return list<string> */
    private static function parseVpnMethods(mixed $v): array
    {
        return self::isObject($v) ? self::strings($v['methods'] ?? null) : [];
    }

    private static function parseBot(mixed $v): ?BotSignals
    {
        if (!self::isObject($v)) {
            return null;
        }
        $info = $v['info'] ?? null;
        $parsed = null;
        if (self::isObject($info) && is_string($info['id'] ?? null)) {
            $parsed = new BotInfo(
                id: $info['id'],
                name: self::optStr($info['name'] ?? null) ?: '',
                provider: self::optStr($info['provider'] ?? null) ?: '',
                category: self::optStr($info['category'] ?? null) ?: 'other',
                identity: self::optStr($info['identity'] ?? null) ?: 'unknown',
            );
        }
        return new BotSignals(
            result: self::optStr($v['result'] ?? null),
            types: self::strings($v['types'] ?? null),
            info: $parsed,
        );
    }
}
