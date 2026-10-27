<?php

declare(strict_types=1);

namespace FpChecker\Events;

final readonly class EligibilityAnswer
{
    /** @param array<array-key, mixed> $raw */
    public function __construct(
        public bool $ok,
        public ?bool $eligible = null,
        public ?string $action = null,
        public ?string $reason = null,
        public ?string $ruleId = null,
        public array $raw = [],
    ) {
    }
}
