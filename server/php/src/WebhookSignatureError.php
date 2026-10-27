<?php

declare(strict_types=1);

namespace FpChecker;

use RuntimeException;

/** `code()` is malformed_header | bad_signature | expired | future. */
final class WebhookSignatureError extends RuntimeException
{
    public function __construct(private readonly string $errorCode)
    {
        parent::__construct('webhook signature: ' . $errorCode);
    }

    /** `getCode()` is final in Exception, so the error code lives here. */
    public function code(): string
    {
        return $this->errorCode;
    }
}
