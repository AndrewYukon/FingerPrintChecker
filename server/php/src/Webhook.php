<?php

declare(strict_types=1);

namespace FpChecker;

use InvalidArgumentException;

/** Verify the `FPC-Signature` header on webhook deliveries. */
final class Webhook
{
    private function __construct()
    {
    }

    /**
     * Return normally if `$header` is a valid, fresh signature of `$rawBody`, else throw
     * WebhookSignatureError. `$rawBody` must be the exact bytes received, not a re-serialised object.
     *
     * @param int|float $toleranceSec allowed clock distance in seconds, in both directions; finite and >= 0
     * @param int|float|null $now verifier clock in unix seconds, or null for the system clock
     * @throws WebhookSignatureError
     * @throws InvalidArgumentException for a negative or non-finite tolerance or clock
     */
    public static function verifyWebhookSignature(
        string $rawBody,
        string $header,
        #[\SensitiveParameter] string $secret,
        int|float $toleranceSec = 300,
        int|float|null $now = null,
    ): void {
        if (!is_finite((float) $toleranceSec) || $toleranceSec < 0) {
            throw new InvalidArgumentException('toleranceSec must be a finite number >= 0');
        }
        if ($now !== null && !is_finite((float) $now)) {
            throw new InvalidArgumentException('now must be a finite number');
        }
        $clock = $now ?? microtime(true);
        [$tRaw, $t, $v1] = self::parseHeader($header);

        $expected = hash_hmac('sha256', $tRaw . '.' . $rawBody, $secret, true);
        $match = false;
        foreach ($v1 as $candidate) {
            // No early exit: keep the work independent of which candidate matched.
            if (preg_match('/\A[0-9a-fA-F]{64}\z/', $candidate) === 1 && hash_equals($expected, (string) hex2bin($candidate))) {
                $match = true;
            }
        }
        if (!$match) {
            throw new WebhookSignatureError('bad_signature');
        }

        if ($clock - $t > $toleranceSec) {
            throw new WebhookSignatureError('expired');
        }
        if ($t - $clock > $toleranceSec) {
            throw new WebhookSignatureError('future');
        }
    }

    /** @return array{0: string, 1: int, 2: list<string>} */
    private static function parseHeader(string $header): array
    {
        if (preg_match('/[ \t\r\n]/', $header) === 1) {
            throw new WebhookSignatureError('malformed_header');
        }
        $t = null;
        $v1 = [];
        foreach (explode(',', $header) as $part) {
            $eq = strpos($part, '=');
            if ($part === '' || $eq === false) {
                throw new WebhookSignatureError('malformed_header');
            }
            $key = substr($part, 0, $eq);
            $value = substr($part, $eq + 1);
            if ($key === 't') {
                if ($t !== null) {
                    throw new WebhookSignatureError('malformed_header');
                }
                $t = $value;
            } elseif ($key === 'v1') {
                $v1[] = $value;
            }
        }
        if ($t === null || preg_match('/\A[0-9]{1,12}\z/', $t) !== 1 || $v1 === []) {
            throw new WebhookSignatureError('malformed_header');
        }
        return [$t, (int) $t, $v1];
    }
}
