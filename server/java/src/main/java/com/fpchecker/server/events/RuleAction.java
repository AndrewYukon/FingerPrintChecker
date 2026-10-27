package com.fpchecker.server.events;

/** What the project's ruleset decided. {@code type}: allow | human_check | deny | none (open string). */
public final class RuleAction {
    public final String type;
    public final String ruleId;
    public final String ruleName;
    public final long rulesetVersion;

    public RuleAction(String type, String ruleId, String ruleName, long rulesetVersion) {
        this.type = type;
        this.ruleId = ruleId;
        this.ruleName = ruleName;
        this.rulesetVersion = rulesetVersion;
    }
}
