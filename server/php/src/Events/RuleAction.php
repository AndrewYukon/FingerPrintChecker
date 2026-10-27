<?php

declare(strict_types=1);

namespace FpChecker\Events;

/** What the project's ruleset decided. `type`: allow | human_check | deny | none (open string). */
final readonly class RuleAction
{
    public function __construct(
        public string $type,
        public ?string $ruleId = null,
        public ?string $ruleName = null,
        public int $rulesetVersion = 0,
    ) {
    }
}
