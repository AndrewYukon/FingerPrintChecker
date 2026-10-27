<?php

declare(strict_types=1);

namespace FpChecker;

/**
 * The forwardable header map for `botCheck`. `botCheck` applies `filter` itself, so Cookie and
 * Authorization never leave your process.
 */
final class BotHeaders
{
    /** The only request headers `botCheck` needs. Never Cookie or Authorization. */
    public const BOT_CHECK_HEADERS = [
        'user-agent',
        'accept',
        'accept-language',
        'accept-encoding',
        'sec-ch-ua',
        'sec-ch-ua-mobile',
        'sec-ch-ua-platform',
        'sec-fetch-site',
        'sec-fetch-mode',
        'sec-fetch-dest',
        'sec-fetch-user',
        'signature',
        'signature-input',
        'signature-agent',
        'upgrade-insecure-requests',
    ];

    /** Never forwarded, even when a signature covers them: they carry credentials. */
    private const NEVER_FORWARD = ['cookie', 'authorization', 'proxy-authorization'];
    private const MAX_EXTRA = 32;

    private function __construct()
    {
    }

    /**
     * Keep the allowed headers plus any header named as a covered component in the request's
     * `signature-input` (so a signed request can be verified), with lower-cased names. Drops everything
     * else; Cookie and Authorization are never forwarded. Headers whose names differ only by case, and
     * list values, are joined with ", ".
     *
     * @param array<array-key, mixed> $headers
     * @return array<string, string>
     */
    public static function filter(array $headers): array
    {
        $every = [];
        foreach ($headers as $name => $value) {
            if ($value === null) {
                continue;
            }
            $key = strtolower((string) $name);
            $text = is_array($value)
                ? implode(', ', array_map(static fn ($v): string => (string) $v, $value))
                : (string) $value;
            $every[$key] = array_key_exists($key, $every) ? $every[$key] . ', ' . $text : $text;
        }
        $extra = array_values(array_filter(
            self::coveredHeaders($every['signature-input'] ?? ''),
            static fn (string $n): bool => !in_array($n, self::NEVER_FORWARD, true),
        ));
        $wanted = array_flip(array_merge(self::BOT_CHECK_HEADERS, array_slice($extra, 0, self::MAX_EXTRA)));
        return array_intersect_key($every, $wanted);
    }

    /** @return list<string> non-`@` component names covered by a `signature-input` value (lower-cased) */
    private static function coveredHeaders(string $signatureInput): array
    {
        $names = [];
        preg_match_all('/\(([^)]*)\)/', $signatureInput, $lists);
        foreach ($lists[1] as $list) {
            preg_match_all('/"([^"]*)"/', $list, $quoted);
            foreach ($quoted[1] as $q) {
                $n = strtolower($q);
                if ($n !== '' && !str_starts_with($n, '@')) {
                    $names[] = $n;
                }
            }
        }
        return $names;
    }
}
