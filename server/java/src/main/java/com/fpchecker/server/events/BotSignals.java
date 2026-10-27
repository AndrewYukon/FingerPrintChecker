package com.fpchecker.server.events;

import java.util.List;

/**
 * {@code signals.bot}. {@code result}: not_detected | good | bad (open; treat an unknown value as {@code bad}),
 * null when not checked. {@code info} is null for version 1 events (stored before server 0.48.0) and when the
 * request did not name a directory bot.
 */
public final class BotSignals {
    public final String result;
    /** Unmodifiable. */
    public final List<String> types;
    public final BotInfo info;

    public BotSignals(String result, List<String> types, BotInfo info) {
        this.result = result;
        this.types = List.copyOf(types);
        this.info = info;
    }
}
