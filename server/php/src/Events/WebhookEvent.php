<?php

declare(strict_types=1);

namespace FpChecker\Events;

/**
 * `ruleAction` and `proxied` are null when the payload lacks them (queued before server 0.45.0);
 * `ruleActionPresent` tells a JSON null from a missing key.
 */
final readonly class WebhookEvent
{
    /**
     * @param list<string> $vpnMethods
     * @param array<array-key, mixed> $raw
     */
    public function __construct(
        public string $visitorId,
        public ?bool $proxied = null,
        public ?RuleAction $ruleAction = null,
        public bool $ruleActionPresent = false,
        public ?MobileSignals $mobile = null,
        public array $vpnMethods = [],
        public array $raw = [],
        public ?int $signalsVersion = null,
        public ?BotSignals $bot = null,
    ) {
    }
}
