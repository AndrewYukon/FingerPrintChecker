package com.fpchecker.server.events;

import com.fasterxml.jackson.databind.JsonNode;

/** Narrowed {@code checkEligibility} response. */
public final class EligibilityAnswer {
    public final boolean ok;
    public final Boolean eligible;
    public final String action;
    public final String reason;
    public final String ruleId;
    public final JsonNode raw;

    public EligibilityAnswer(boolean ok, Boolean eligible, String action, String reason, String ruleId, JsonNode raw) {
        this.ok = ok;
        this.eligible = eligible;
        this.action = action;
        this.reason = reason;
        this.ruleId = ruleId;
        this.raw = raw;
    }
}
