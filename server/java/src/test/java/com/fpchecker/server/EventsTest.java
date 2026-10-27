package com.fpchecker.server;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fpchecker.server.events.EligibilityAnswer;
import com.fpchecker.server.events.Events;
import com.fpchecker.server.events.MobileSignals;
import com.fpchecker.server.events.RuleAction;
import com.fpchecker.server.events.WebhookEvent;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class EventsTest {
    private static final ObjectMapper M = new ObjectMapper();
    private static final JsonNode V = load();

    private static JsonNode load() {
        try {
            return M.readTree(Files.readAllBytes(Paths.get("../../test-vectors/webhook-signature.json")));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static JsonNode vector(String name) {
        for (JsonNode c : V.get("cases")) {
            if (c.get("name").asText().equals(name)) {
                return c;
            }
        }
        throw new AssertionError("no vector " + name);
    }

    private static String ev(String dataExtra) {
        return "{\"id\":\"evt_1\",\"type\":\"identify\",\"data\":{\"visitorId\":\"v_1\"" + dataExtra + "}}";
    }

    private static void verifyVector(JsonNode c) {
        Webhook.verifyWebhookSignature(c.get("body").asText().getBytes(StandardCharsets.UTF_8), c.get("header").asText(),
                V.get("secret").asText(), 300, c.get("now").asLong());
    }

    @Test
    void okRuleActionVectorVerifiesAndParses() {
        JsonNode c = vector("ok_rule_action");
        assertDoesNotThrow(() -> verifyVector(c));
        WebhookEvent e = Events.parseWebhookEvent(c.get("body").asText());
        assertEquals(Boolean.TRUE, e.proxied);
        RuleAction ra = e.ruleAction;
        assertEquals("deny", ra.type);
        assertEquals("r_0a1b2c3d", ra.ruleId);
        assertEquals("Block hosting", ra.ruleName);
        assertEquals(3, ra.rulesetVersion);
    }

    @ParameterizedTest
    @ValueSource(strings = {"allow", "human_check", "deny", "none"})
    void ruleActionTypes(String t) {
        WebhookEvent e = Events.parseWebhookEvent(
                ev(",\"ruleAction\":{\"type\":\"" + t + "\",\"rulesetVersion\":1},\"proxied\":false"));
        assertEquals(t, e.ruleAction.type);
        assertNull(e.ruleAction.ruleId);
        assertEquals(Boolean.FALSE, e.proxied);
    }

    @Test
    void nullAndMissingRuleAction() {
        WebhookEvent n = Events.parseWebhookEvent(ev(",\"ruleAction\":null"));
        assertNull(n.ruleAction);
        assertTrue(n.ruleActionPresent);
        WebhookEvent old = Events.parseWebhookEvent(ev(""));
        assertNull(old.ruleAction);
        assertFalse(old.ruleActionPresent);
        assertNull(old.proxied);
    }

    @Test
    void unknownRuleTypeDoesNotThrow() {
        assertEquals("captcha",
                Events.parseWebhookEvent(ev(",\"ruleAction\":{\"type\":\"captcha\",\"rulesetVersion\":2}")).ruleAction.type);
    }

    @Test
    void nonIntegerRulesetVersionIsZero() {
        assertEquals(0, Events.parseWebhookEvent(ev(",\"ruleAction\":{\"type\":\"allow\",\"rulesetVersion\":1.5}")).ruleAction.rulesetVersion);
        assertEquals(0, Events.parseWebhookEvent(ev(",\"ruleAction\":{\"type\":\"allow\",\"rulesetVersion\":true}")).ruleAction.rulesetVersion);
        assertEquals(0, Events.parseWebhookEvent(ev(",\"ruleAction\":{\"type\":\"allow\"}")).ruleAction.rulesetVersion);
    }

    @Test
    void rejectsNonEvent() {
        assertThrows(IllegalArgumentException.class, () -> Events.parseWebhookEvent("{\"a\":1}"));
        assertThrows(IllegalArgumentException.class, () -> Events.parseWebhookEvent("[1]"));
        assertThrows(IllegalArgumentException.class, () -> Events.parseWebhookEvent("not json"));
        assertThrows(IllegalArgumentException.class, () -> Events.parseWebhookEvent("{\"data\":{\"visitorId\":5}}"));
    }

    @Test
    void eligibilityRuleId() throws Exception {
        EligibilityAnswer a = Events.parseEligibilityAnswer(M.readTree(
                "{\"ok\":true,\"eligible\":false,\"action\":\"deny\",\"reason\":\"rule_deny\",\"ruleId\":\"r_1\"}"));
        assertTrue(a.ok);
        assertEquals("r_1", a.ruleId);
        assertEquals("rule_deny", a.reason);
        assertEquals("deny", a.action);
        assertEquals(Boolean.FALSE, a.eligible);
        assertNull(Events.parseEligibilityAnswer(M.readTree("{\"ok\":true,\"eligible\":true,\"reason\":\"brand_new\"}")).ruleId);
        assertFalse(Events.parseEligibilityAnswer(M.readTree("{\"ok\":\"yes\"}")).ok);
        assertThrows(IllegalArgumentException.class, () -> Events.parseEligibilityAnswer(M.readTree("[]")));
        assertThrows(IllegalArgumentException.class, () -> Events.parseEligibilityAnswer(null));
    }

    @Test
    void okMobileSignalsVectorVerifiesAndParses() {
        JsonNode c = vector("ok_mobile_signals");
        assertDoesNotThrow(() -> verifyVector(c));
        WebhookEvent e = Events.parseWebhookEvent(c.get("body").asText());
        MobileSignals m = e.mobile;
        assertEquals(Boolean.TRUE, m.rooted);
        assertEquals(Boolean.FALSE, m.hooked);
        assertEquals(Boolean.TRUE, m.developerMode);
        assertEquals(Boolean.TRUE, m.vpn);
        assertNull(m.locationSpoofed);
        assertNull(m.factoryResetAt);
        assertTrue(e.vpnMethods.contains("os_vpn"));
    }

    @Test
    void oldPayloadNewFieldsAreNull() {
        MobileSignals m = Events.parseWebhookEvent(ev(
                ",\"signals\":{\"mobile\":{\"emulator\":false,\"attested\":true,\"integrity\":\"strong\"}}")).mobile;
        assertNull(m.rooted);
        assertNull(m.clonedApp);
        assertNull(m.factoryResetAt);
        assertEquals("strong", m.integrity);
        assertEquals(Boolean.FALSE, m.emulator);
        assertNull(Events.parseWebhookEvent(ev(",\"signals\":{\"mobile\":null}")).mobile);
        WebhookEvent e = Events.parseWebhookEvent(ev(""));
        assertNull(e.mobile);
        assertTrue(e.vpnMethods.isEmpty());
    }

    @Test
    void nonBooleanReadsAsNullAndUnknownVpnMethodKept() {
        WebhookEvent e = Events.parseWebhookEvent(ev(
                ",\"signals\":{\"vpn\":{\"result\":true,\"methods\":[\"os_vpn\",\"future\",5]},"
                        + "\"mobile\":{\"rooted\":\"yes\",\"factoryResetAt\":5,\"integrity\":\"weird\"}}"));
        assertNull(e.mobile.rooted);
        assertNull(e.mobile.factoryResetAt);
        assertNull(e.mobile.integrity);
        assertEquals(List.of("os_vpn", "future"), e.vpnMethods);
    }

    @Test
    void signalsVersionOnlyOneOrTwo() {
        assertNull(Events.parseWebhookEvent(ev(",\"signals\":{\"version\":3}")).signalsVersion);
        assertNull(Events.parseWebhookEvent(ev(",\"signals\":{\"version\":1.0}")).signalsVersion);
        assertNull(Events.parseWebhookEvent(ev(",\"signals\":{\"version\":true}")).signalsVersion);
        assertEquals(Integer.valueOf(2), Events.parseWebhookEvent(ev(",\"signals\":{\"version\":2}")).signalsVersion);
    }

    @Test
    void collectionsAreImmutable() {
        WebhookEvent e = Events.parseWebhookEvent(ev(",\"signals\":{\"vpn\":{\"methods\":[\"a\"]}}"));
        assertThrows(UnsupportedOperationException.class, () -> e.vpnMethods.add("b"));
        assertEquals("evt_1", e.raw.get("id").asText());
    }
}
