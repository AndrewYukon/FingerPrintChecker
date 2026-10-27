<?php

declare(strict_types=1);

namespace FpChecker;

use LogicException;

/**
 * Holds a key so that no plain copy sits in any inspectable property. var_export, (array) casts,
 * var_dump and debug_zval_dump ignore __debugInfo, so the value is stored XOR-masked with a random
 * per-instance pad: dumps show only masked bytes.
 *
 * @internal
 */
final class Secret
{
    private string $pad;
    private string $masked;

    public function __construct(#[\SensitiveParameter] string $value)
    {
        $this->pad = $value === '' ? '' : random_bytes(strlen($value));
        $this->masked = $value ^ $this->pad;
    }

    public function reveal(): string
    {
        return $this->masked ^ $this->pad;
    }

    /** @return array<string, string> */
    public function __debugInfo(): array
    {
        return ['value' => '***'];
    }

    /** @return array<string, mixed> */
    public function __serialize(): array
    {
        throw new LogicException('FpChecker: secrets cannot be serialized');
    }
}
