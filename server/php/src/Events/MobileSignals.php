<?php

declare(strict_types=1);

namespace FpChecker\Events;

/**
 * Device-state signals of an android, ios or macos event. Each flag is true (detected), false (checked,
 * nothing found) or null (not checked: old SDK, probes switched off, unsupported platform). Not a guarantee
 * either way. `factoryResetAt` is reserved and currently always null.
 */
final readonly class MobileSignals
{
    public function __construct(
        public ?bool $emulator = null,
        public ?bool $attested = null,
        public ?string $integrity = null,
        public ?bool $rooted = null,
        public ?bool $hooked = null,
        public ?bool $debugger = null,
        public ?bool $developerMode = null,
        public ?bool $mitm = null,
        public ?bool $vpn = null,
        public ?bool $locationSpoofed = null,
        public ?bool $clonedApp = null,
        public ?string $factoryResetAt = null,
    ) {
    }
}
