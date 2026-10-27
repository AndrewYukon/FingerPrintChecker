package com.fpchecker.server.events;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/**
 * Typed view of a webhook body. {@code ruleAction} and {@code proxied} are null when the payload lacks them
 * (queued before server 0.45.0); {@code ruleActionPresent} tells a JSON null from a missing key.
 */
public final class WebhookEvent {
    public final String visitorId;
    public final Boolean proxied;
    public final RuleAction ruleAction;
    public final boolean ruleActionPresent;
    public final MobileSignals mobile;
    /** Unmodifiable. */
    public final List<String> vpnMethods;
    /** The full parsed body. */
    public final JsonNode raw;
    /** 1 before server 0.48.0, 2 since; null when absent or unknown. */
    public final Integer signalsVersion;
    public final BotSignals bot;

    public WebhookEvent(String visitorId, Boolean proxied, RuleAction ruleAction, boolean ruleActionPresent,
            MobileSignals mobile, List<String> vpnMethods, JsonNode raw, Integer signalsVersion, BotSignals bot) {
        this.visitorId = visitorId;
        this.proxied = proxied;
        this.ruleAction = ruleAction;
        this.ruleActionPresent = ruleActionPresent;
        this.mobile = mobile;
        this.vpnMethods = List.copyOf(vpnMethods);
        this.raw = raw;
        this.signalsVersion = signalsVersion;
        this.bot = bot;
    }
}
