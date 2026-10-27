package com.fpchecker.server.events;

/**
 * Device-state signals of an android, ios or macos event. Each flag is TRUE (detected), FALSE (checked, nothing
 * found) or null (not checked: old SDK, probes switched off, unsupported platform). Not a guarantee either
 * way. {@code factoryResetAt} is reserved and currently always null.
 */
public final class MobileSignals {
    public final Boolean emulator;
    public final Boolean attested;
    /** strong | basic | failed, else null. */
    public final String integrity;
    public final Boolean rooted;
    public final Boolean hooked;
    public final Boolean debugger;
    public final Boolean developerMode;
    public final Boolean mitm;
    public final Boolean vpn;
    public final Boolean locationSpoofed;
    public final Boolean clonedApp;
    public final String factoryResetAt;

    public MobileSignals(Boolean emulator, Boolean attested, String integrity, Boolean rooted, Boolean hooked,
            Boolean debugger, Boolean developerMode, Boolean mitm, Boolean vpn, Boolean locationSpoofed,
            Boolean clonedApp, String factoryResetAt) {
        this.emulator = emulator;
        this.attested = attested;
        this.integrity = integrity;
        this.rooted = rooted;
        this.hooked = hooked;
        this.debugger = debugger;
        this.developerMode = developerMode;
        this.mitm = mitm;
        this.vpn = vpn;
        this.locationSpoofed = locationSpoofed;
        this.clonedApp = clonedApp;
        this.factoryResetAt = factoryResetAt;
    }
}
