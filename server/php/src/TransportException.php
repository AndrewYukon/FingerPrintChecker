<?php

declare(strict_types=1);

namespace FpChecker;

use RuntimeException;

/**
 * A transport could not complete the round trip. Keep the message free of request data.
 *
 * @internal
 */
final class TransportException extends RuntimeException
{
    public function __construct(string $message, private readonly bool $timedOut = false)
    {
        parent::__construct($message);
    }

    public function isTimeout(): bool
    {
        return $this->timedOut;
    }
}
