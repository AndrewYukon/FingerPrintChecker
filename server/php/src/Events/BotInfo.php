<?php

declare(strict_types=1);

namespace FpChecker\Events;

/**
 * One entry of the Bot directory and how well the request matched it. `category` and `identity` are open
 * strings: treat an unknown category as `other`.
 */
final readonly class BotInfo
{
    public function __construct(
        public string $id,
        public string $name,
        public string $provider,
        public string $category,
        public string $identity,
    ) {
    }
}
