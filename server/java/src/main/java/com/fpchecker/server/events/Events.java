package com.fpchecker.server.events;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;

/**
 * Typed views of webhook events and eligibility answers. Reasons and rule types are open strings: the server
 * may add values, and an unknown one never throws.
 */
public final class Events {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Events() {}

    private static String optStr(JsonNode v) {
        return v != null && v.isTextual() ? v.asText() : null;
    }

    private static String orDefault(String s, String fallback) {
        return s == null || s.isEmpty() ? fallback : s;
    }

    private static Boolean tri(JsonNode v) {
        return v != null && v.isBoolean() ? Boolean.valueOf(v.asBoolean()) : null;
    }

    private static RuleAction parseRuleAction(JsonNode v) {
        if (v == null || !v.isObject() || !v.path("type").isTextual()) {
            return null;
        }
        JsonNode version = v.get("rulesetVersion");
        long rulesetVersion = version != null && version.isIntegralNumber() && version.canConvertToLong()
                ? version.asLong() : 0;
        return new RuleAction(v.get("type").asText(), optStr(v.get("ruleId")), optStr(v.get("ruleName")),
                rulesetVersion);
    }

    private static MobileSignals parseMobile(JsonNode v) {
        if (v == null || !v.isObject()) {
            return null;
        }
        String integrity = optStr(v.get("integrity"));
        boolean knownIntegrity = "strong".equals(integrity) || "basic".equals(integrity) || "failed".equals(integrity);
        return new MobileSignals(tri(v.get("emulator")), tri(v.get("attested")), knownIntegrity ? integrity : null,
                tri(v.get("rooted")), tri(v.get("hooked")), tri(v.get("debugger")), tri(v.get("developerMode")),
                tri(v.get("mitm")), tri(v.get("vpn")), tri(v.get("locationSpoofed")), tri(v.get("clonedApp")),
                optStr(v.get("factoryResetAt")));
    }

    private static List<String> strings(JsonNode arr) {
        List<String> out = new ArrayList<>();
        if (arr != null && arr.isArray()) {
            for (JsonNode m : arr) {
                if (m.isTextual()) {
                    out.add(m.asText());
                }
            }
        }
        return out;
    }

    private static List<String> parseVpnMethods(JsonNode v) {
        return v != null && v.isObject() ? strings(v.get("methods")) : new ArrayList<>();
    }

    private static BotSignals parseBot(JsonNode v) {
        if (v == null || !v.isObject()) {
            return null;
        }
        JsonNode info = v.get("info");
        BotInfo parsed = null;
        if (info != null && info.isObject() && info.path("id").isTextual()) {
            parsed = new BotInfo(info.get("id").asText(),
                    orDefault(optStr(info.get("name")), ""),
                    orDefault(optStr(info.get("provider")), ""),
                    orDefault(optStr(info.get("category")), "other"),
                    orDefault(optStr(info.get("identity")), "unknown"));
        }
        return new BotSignals(optStr(v.get("result")), strings(v.get("types")), parsed);
    }

    /**
     * Parse a webhook body (verify its signature first).
     *
     * @throws IllegalArgumentException when the body is not JSON or not a webhook event
     */
    public static WebhookEvent parseWebhookEvent(String rawBody) {
        JsonNode body;
        try {
            body = MAPPER.readTree(rawBody);
        } catch (JsonProcessingException | RuntimeException e) {
            throw new IllegalArgumentException("parseWebhookEvent: not JSON");
        }
        JsonNode data = body == null ? null : body.get("data");
        if (data == null || !data.isObject() || !data.path("visitorId").isTextual()) {
            throw new IllegalArgumentException("parseWebhookEvent: not a webhook event");
        }
        JsonNode signals = data.get("signals") != null && data.get("signals").isObject() ? data.get("signals")
                : MAPPER.createObjectNode();
        JsonNode version = signals.get("version");
        Integer signalsVersion = version != null && version.isIntegralNumber() && version.canConvertToInt()
                && (version.asInt() == 1 || version.asInt() == 2) ? Integer.valueOf(version.asInt()) : null;
        return new WebhookEvent(
                data.get("visitorId").asText(),
                tri(data.get("proxied")),
                parseRuleAction(data.get("ruleAction")),
                data.has("ruleAction"),
                parseMobile(signals.get("mobile")),
                parseVpnMethods(signals.get("vpn")),
                body,
                signalsVersion,
                parseBot(signals.get("bot")));
    }

    /**
     * Narrow a {@code checkEligibility} response; {@code ruleId} is surfaced when present.
     *
     * @throws IllegalArgumentException when {@code body} is not a JSON object
     */
    public static EligibilityAnswer parseEligibilityAnswer(JsonNode body) {
        if (body == null || !body.isObject()) {
            throw new IllegalArgumentException("parseEligibilityAnswer: not an object");
        }
        return new EligibilityAnswer(
                body.path("ok").isBoolean() && body.get("ok").asBoolean(),
                tri(body.get("eligible")),
                optStr(body.get("action")),
                optStr(body.get("reason")),
                optStr(body.get("ruleId")),
                body);
    }
}
