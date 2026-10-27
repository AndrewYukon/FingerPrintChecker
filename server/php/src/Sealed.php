<?php

declare(strict_types=1);

namespace FpChecker;

use JsonException;

/** Decrypt the `sealedResult` blob returned by /v2/identify. */
final class Sealed
{
    private const MAGIC = 'fps1';
    private const MIN_LEN = 4 + 4 + 12 + 16;

    private function __construct()
    {
    }

    /**
     * Decrypt a sealed result. `$keys` are base64 32-byte project keys (pass active and previous during
     * rotation).
     *
     * @param iterable<mixed> $keys
     * @return array<string, mixed>
     * @throws SealedResultError
     */
    public static function unsealResult(mixed $blob, #[\SensitiveParameter] mixed $keys): array
    {
        if (!is_iterable($keys)) {
            throw new SealedResultError('invalid_key');
        }
        $keyBytes = [];
        foreach ($keys as $k) {
            $b = self::strictB64($k);
            if ($b === null || strlen($b) !== 32) {
                throw new SealedResultError('invalid_key');
            }
            $keyBytes[] = $b;
        }

        $raw = self::strictB64($blob);
        if ($raw === null || strlen($raw) < self::MIN_LEN || substr($raw, 0, 4) !== self::MAGIC) {
            throw new SealedResultError('bad_format');
        }

        $aad = substr($raw, 0, 8);
        $keyId = substr($raw, 4, 4);
        $candidates = array_values(array_filter(
            $keyBytes,
            static fn (#[\SensitiveParameter] string $k): bool => substr(hash('sha256', $k, true), 0, 4) === $keyId,
        ));
        if ($candidates === []) {
            throw new SealedResultError('unknown_key');
        }

        $nonce = substr($raw, 8, 12);
        $rest = substr($raw, 20);
        $tag = substr($rest, -16);
        $cipher = substr($rest, 0, -16);
        $plain = null;
        foreach ($candidates as $key) {
            $out = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
            if ($out !== false) {
                $plain = $out;
                break;
            }
        }
        if ($plain === null) {
            throw new SealedResultError('decrypt_failed');
        }

        // JSON object only (a "[]" would also decode to an array); invalid UTF-8, NaN and Infinity are
        // JSON syntax errors; too-deep nesting is an error at depth 512.
        if ((ltrim($plain, " \t\r\n")[0] ?? '') !== '{') {
            throw new SealedResultError('decrypt_failed');
        }
        try {
            $parsed = json_decode($plain, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new SealedResultError('decrypt_failed');
        }
        if (!is_array($parsed)) {
            throw new SealedResultError('decrypt_failed');
        }
        $version = $parsed['version'] ?? null;
        if (!(is_int($version) || is_float($version)) || $version != 1) {
            throw new SealedResultError('unsupported_version');
        }
        return $parsed;
    }

    /** Canonical standard base64 only (regex, length, decode, re-encode equality). */
    private static function strictB64(#[\SensitiveParameter] mixed $value): ?string
    {
        if (!is_string($value) || strlen($value) % 4 !== 0 || preg_match('/\A[A-Za-z0-9+\/]*={0,2}\z/', $value) !== 1) {
            return null;
        }
        $raw = base64_decode($value, true);
        return $raw !== false && base64_encode($raw) === $value ? $raw : null;
    }
}
