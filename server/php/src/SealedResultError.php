<?php

declare(strict_types=1);

namespace FpChecker;

use RuntimeException;

/** `code()` is bad_format | unknown_key | decrypt_failed | invalid_key | unsupported_version. */
final class SealedResultError extends RuntimeException
{
    public function __construct(private readonly string $errorCode)
    {
        parent::__construct('sealed result: ' . $errorCode);
    }

    /** `getCode()` is final in Exception, so the error code lives here. */
    public function code(): string
    {
        return $this->errorCode;
    }
}
