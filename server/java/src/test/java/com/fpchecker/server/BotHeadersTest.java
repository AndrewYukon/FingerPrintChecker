package com.fpchecker.server;

import static com.fpchecker.server.FakeTransport.resp;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fpchecker.server.events.Events;
import com.fpchecker.server.events.WebhookEvent;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class BotHeadersTest {
    private static final ObjectMapper M = new ObjectMapper();
    private static final String VERDICT = "{\"bot\":{\"result\":\"good\",\"types\":[],\"info\":{\"id\":\"googlebot\","
            + "\"name\":\"Googlebot\",\"provider\":\"Google\",\"category\":\"search_crawler\",\"identity\":\"verified\"}},"
            + "\"ip\":{\"country\":\"US\"}}";
    private static final String SIG_INPUT = "sig1=(\"@authority\" \"content-type\" \"X-Custom\" \"cookie\" "
            + "\"signature-agent\");created=1;keyid=\"k\";tag=\"web-bot-auth\"";

    private final java.util.List<java.time.Duration> sleeps = new java.util.ArrayList<>();

    private FpChecker mk(FakeTransport t) {
        return new FpChecker(FpChecker.builder("sk_test_123"), t, sleeps::add);
    }

    private static Map<String, String> map(String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put(kv[i], kv[i + 1]);
        }
        return m;
    }

    @Test
    void botCheckPostsBodyAndParsesVerdict() throws Exception {
        FakeTransport t = new FakeTransport(resp(200, VERDICT));
        JsonNode out = mk(t).botCheck("GET", "https://shop.example/pricing", "66.249.66.1",
                map("user-agent", "Googlebot/2.1"));
        Transport.Request req = t.calls.get(0);
        assertEquals("https://api.fpchecker.com/v1/bot-check", req.url);
        assertEquals("POST", req.method);
        assertEquals(M.readTree("{\"method\":\"GET\",\"url\":\"https://shop.example/pricing\",\"ip\":\"66.249.66.1\","
                + "\"headers\":{\"user-agent\":\"Googlebot/2.1\"}}"), M.readTree(req.body));
        assertEquals("sk_test_123", FakeTransport.header(req, "X-Secret-Key"));
        assertEquals("good", out.get("bot").get("result").asText());
        assertEquals("verified", out.get("bot").get("info").get("identity").asText());
    }

    @Test
    void botCheck400CarriesErrorAndField() {
        FakeTransport t = new FakeTransport(resp(400, "{\"ok\":false,\"error\":\"invalid_ip\",\"field\":\"ip\"}"));
        FpCheckerApiException e = assertThrows(FpCheckerApiException.class,
                () -> mk(t).botCheck("GET", "https://x.test/", "bad", map()));
        assertEquals(400, e.status());
        assertEquals("invalid_ip", e.code());
        assertEquals("ip", e.body().get("field").asText());
    }

    @ParameterizedTest
    @ValueSource(ints = {401, 429})
    void botCheck401And429RaiseWithoutRetry(int status) {
        FakeTransport t = new FakeTransport(resp(status, "{\"ok\":false,\"error\":\"x\"}"), resp(200, VERDICT));
        FpCheckerApiException e = assertThrows(FpCheckerApiException.class,
                () -> mk(t).botCheck("GET", "https://x.test/", "1.1.1.1", map()));
        assertEquals(status, e.status());
        assertEquals(1, t.calls.size());
    }

    @Test
    void searchEventsPassesBotFiltersAsQuery() {
        FakeTransport t = new FakeTransport(resp(200, "{\"ok\":true}"));
        Map<String, Object> q = new LinkedHashMap<>();
        q.put("bot_result", "good");
        q.put("bot_category", "ai_crawler");
        q.put("bot_identity", "signed");
        q.put("bot_id", "googlebot");
        mk(t).searchEvents(q);
        assertTrue(t.calls.get(0).url.endsWith(
                "/v1/events?bot_result=good&bot_category=ai_crawler&bot_identity=signed&bot_id=googlebot"));
    }

    @Test
    void headerHelperKeepsAllowedSetAndDropsCookieAuthorization() {
        Map<String, String> allowed = map("User-Agent", "UA", "Accept", "text/html", "Accept-Language", "en",
                "Accept-Encoding", "gzip", "Sec-CH-UA", "\"x\"", "Sec-CH-UA-Mobile", "?0",
                "Sec-CH-UA-Platform", "\"macOS\"", "Sec-Fetch-Site", "none", "Sec-Fetch-Mode", "navigate",
                "Sec-Fetch-Dest", "document", "Sec-Fetch-User", "?1", "Signature", "sig1=:a:",
                "Signature-Input", "sig1=()", "Signature-Agent", "\"https://chatgpt.com\"",
                "Upgrade-Insecure-Requests", "1");
        Map<String, String> in = new LinkedHashMap<>(allowed);
        in.put("Cookie", "sid=1");
        in.put("Authorization", "Bearer x");
        in.put("X-Forwarded-For", "1.1.1.1");
        Map<String, String> expected = new LinkedHashMap<>();
        allowed.forEach((k, v) -> expected.put(k.toLowerCase(java.util.Locale.ROOT), v));
        assertEquals(expected, BotHeaders.filter(in));
        assertEquals(15, BotHeaders.BOT_CHECK_HEADERS.size());
        assertThrows(UnsupportedOperationException.class, () -> BotHeaders.BOT_CHECK_HEADERS.add("x"));
    }

    @Test
    void headerHelperJoinsHeadersDifferingOnlyByCase() {
        assertEquals(map("accept", "a, b"), BotHeaders.filter(map("Accept", "a", "accept", "b", "Cookie", "c")));
    }

    @Test
    void headerHelperSkipsNullValuesAndNullMap() {
        Map<String, String> in = new LinkedHashMap<>();
        in.put("accept", null);
        in.put("user-agent", "u");
        assertEquals(map("user-agent", "u"), BotHeaders.filter(in));
        assertTrue(BotHeaders.filter(null).isEmpty());
    }

    @Test
    void headerHelperKeepsSignatureInputCoveredComponents() {
        Map<String, String> out = BotHeaders.filter(map("Signature-Input", SIG_INPUT,
                "Signature-Agent", "\"https://chatgpt.com\"", "Content-Type", "text/plain", "X-Custom", "v",
                "X-Other", "no", "Cookie", "sid=1", "Authorization", "x"));
        assertEquals("text/plain", out.get("content-type"));
        assertEquals("v", out.get("x-custom"));
        assertFalse(out.containsKey("x-other"));
        assertFalse(out.containsKey("cookie"));
        assertFalse(out.containsKey("authorization"));
    }

    @Test
    void headerHelperCapsCoveredExtrasAt32() {
        StringBuilder names = new StringBuilder();
        Map<String, String> in = map();
        for (int i = 0; i < 40; i++) {
            names.append("\"x-h").append(i).append("\" ");
            in.put("x-h" + i, "v");
        }
        in.put("signature-input", "sig1=(" + names + ")");
        Map<String, String> out = BotHeaders.filter(in);
        assertEquals(33, out.size()); // 32 extras + signature-input itself
        assertTrue(out.containsKey("x-h31"));
        assertFalse(out.containsKey("x-h32"));
    }

    @Test
    void headerHelperNoExtrasWithoutSignatureInput() {
        assertEquals(map("user-agent", "u"), BotHeaders.filter(map("content-type", "x", "user-agent", "u")));
    }

    private static String ev(String signals) {
        return "{\"id\":\"e\",\"type\":\"identify\",\"data\":{\"visitorId\":\"v_1\",\"signals\":" + signals + "}}";
    }

    @Test
    void v1EventParsesWithoutInfo() {
        WebhookEvent e = Events.parseWebhookEvent(ev("{\"version\":1,\"bot\":{\"result\":\"bad\",\"types\":[\"webdriver\"]}}"));
        assertEquals(Integer.valueOf(1), e.signalsVersion);
        assertEquals("bad", e.bot.result);
        assertEquals(List.of("webdriver"), e.bot.types);
        assertEquals(null, e.bot.info);
    }

    @Test
    void v2EventParsesGoodAndInfo() {
        String info = "{\"id\":\"googlebot\",\"name\":\"Googlebot\",\"provider\":\"Google\","
                + "\"category\":\"search_crawler\",\"identity\":\"verified\"}";
        WebhookEvent e = Events.parseWebhookEvent(ev("{\"version\":2,\"bot\":{\"result\":\"good\",\"types\":[],\"info\":" + info + "}}"));
        assertEquals(Integer.valueOf(2), e.signalsVersion);
        assertEquals("good", e.bot.result);
        assertEquals("googlebot", e.bot.info.id);
        assertEquals("search_crawler", e.bot.info.category);
        assertEquals("verified", e.bot.info.identity);
        assertEquals(null, Events.parseWebhookEvent(ev("{\"version\":2,\"bot\":{\"result\":\"not_detected\",\"types\":[],"
                + "\"info\":null}}")).bot.info);
    }

    @Test
    void eventWithoutSignalsHasNoBot() {
        WebhookEvent e = Events.parseWebhookEvent("{\"data\":{\"visitorId\":\"v_1\"}}");
        assertEquals(null, e.bot);
        assertEquals(null, e.signalsVersion);
    }

    @Test
    void unknownBotInfoDefaults() {
        WebhookEvent e = Events.parseWebhookEvent(ev("{\"version\":2,\"bot\":{\"result\":\"good\",\"info\":{\"id\":\"x\"}}}"));
        assertEquals("", e.bot.info.name);
        assertEquals("other", e.bot.info.category);
        assertEquals("unknown", e.bot.info.identity);
        assertTrue(e.bot.types.isEmpty());
    }
}
