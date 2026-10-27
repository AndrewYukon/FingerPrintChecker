<?php

declare(strict_types=1);

namespace FpChecker\Events;

/**
 * `signals.bot`. `result`: not_detected | good | bad (open; treat an unknown value as `bad`), null when not
 * checked. `info` is null for version 1 events (stored before server 0.48.0) and when the request did not
 * name a directory bot.
 */
final readonly class BotSignals
{
    /** @param list<string> $types */
    public function __construct(
        public ?string $result = null,
        public array $types = [],
        public ?BotInfo $info = null,
    ) {
    }
}
