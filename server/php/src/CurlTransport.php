<?php

declare(strict_types=1);

namespace FpChecker;

/** @internal */
final class CurlTransport implements Transport
{
    public function send(
        string $method,
        string $url,
        #[\SensitiveParameter] array $headers,
        ?string $body,
        float $timeout,
    ): array {
        $lines = ['Expect:'];
        foreach ($headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }
        $responseHeaders = [];
        $ch = curl_init();
        if ($ch === false) {
            throw new TransportException('curl_init failed');
        }
        $ms = max(1, (int) ceil($timeout * 1000));
        $options = [
            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_RETURNTRANSFER => true,
            // A redirect would forward X-Secret-Key to another origin: never follow.
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_CONNECTTIMEOUT_MS => $ms,
            CURLOPT_TIMEOUT_MS => $ms,
            CURLOPT_NOSIGNAL => true,
            CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (&$responseHeaders): int {
                if (str_starts_with($line, 'HTTP/')) {
                    $responseHeaders = []; // a new status block (e.g. after 100 Continue) replaces the old one
                } elseif (($pos = strpos($line, ':')) !== false) {
                    $responseHeaders[strtolower(trim(substr($line, 0, $pos)))] = trim(substr($line, $pos + 1));
                }
                return strlen($line);
            },
        ];
        // CURLOPT_PROTOCOLS is deprecated in newer libcurl; the string form replaces it where defined.
        if (defined('CURLOPT_PROTOCOLS_STR')) {
            $options[CURLOPT_PROTOCOLS_STR] = 'http,https';
        } else {
            $options[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
        }
        if ($body !== null) {
            $options[CURLOPT_POSTFIELDS] = $body;
        }
        curl_setopt_array($ch, $options);

        $raw = curl_exec($ch);
        $errno = curl_errno($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        unset($ch);

        if ($raw === false || $errno !== 0) {
            // curl_strerror only: curl_error() could echo parts of the URL.
            throw new TransportException(
                'curl error ' . $errno . ': ' . curl_strerror($errno),
                $errno === CURLE_OPERATION_TIMEDOUT,
            );
        }
        return ['status' => $status, 'headers' => $responseHeaders, 'body' => (string) $raw];
    }
}
