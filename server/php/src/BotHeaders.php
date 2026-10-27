<?php

declare(strict_types=1);

namespace FpChecker;

/** Task 4 replaces this pass-through with the real allowlist filter. */
final class BotHeaders
{
    /**
     * @param array<string, string> $headers
     * @return array<string, string>
     */
    public static function filter(array $headers): array
    {
        return $headers;
    }
}
