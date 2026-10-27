package com.fpchecker.server;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class WebhookTest {
    private static final JsonNode V = load();
    private static final String SECRET = V.get("secret").asText();

    private static JsonNode load() {
        try {
            return new ObjectMapper().readTree(Files.readAllBytes(Paths.get("../../test-vectors/webhook-signature.json")));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static List<JsonNode> cases() {
        List<JsonNode> out = new ArrayList<>();
        V.get("cases").forEach(out::add);
        return out;
    }

    static String sign(byte[] body, long t) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update(Long.toString(t).getBytes(StandardCharsets.US_ASCII));
            mac.update((byte) '.');
            StringBuilder hex = new StringBuilder();
            for (byte b : mac.doFinal(body)) {
                hex.append(String.format("%02x", b));
            }
            return "t=" + t + ",v1=" + hex;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String code(Runnable r) {
        return assertThrows(WebhookSignatureException.class, r::run).code();
    }

    @Test
    void vectorCountIsNotFiltered() {
        assertEquals(17, cases().size());
    }

    @ParameterizedTest
    @MethodSource("cases")
    void webhookVector(JsonNode c) {
        byte[] body = c.get("body").asText().getBytes(StandardCharsets.UTF_8);
        String header = c.get("header").asText();
        long now = c.get("now").asLong();
        JsonNode expect = c.get("expect");
        if (expect.isBoolean() && expect.asBoolean()) {
            assertDoesNotThrow(() -> Webhook.verifyWebhookSignature(body, header, SECRET, 300, now));
        } else {
            assertEquals(expect.get("error").asText(),
                    code(() -> Webhook.verifyWebhookSignature(body, header, SECRET, 300, now)));
        }
    }

    @Test
    void staleTimestampRejectedEvenWithValidSignature() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        String header = sign(body, 1000);
        assertDoesNotThrow(() -> Webhook.verifyWebhookSignature(body, header, SECRET, 300, 1300L));
        assertEquals("expired", code(() -> Webhook.verifyWebhookSignature(body, header, SECRET, 300, 1301L)));
        assertEquals("future", code(() -> Webhook.verifyWebhookSignature(body, header, SECRET, 300, 699L)));
        // default tolerance (300) against the real clock: a signature from 1970 is stale
        assertEquals("expired", code(() -> Webhook.verifyWebhookSignature(body, header, SECRET)));
    }

    @Test
    void v0OnlyHeaderRejected() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        String mac = sign(body, 1000).split("v1=")[1];
        assertEquals("malformed_header",
                code(() -> Webhook.verifyWebhookSignature(body, "t=1000,v0=" + mac, SECRET, 300, 1000L)));
    }

    @Test
    void stringBodyAcceptedAndDefaultNow() {
        long t = System.currentTimeMillis() / 1000;
        String body = "{\"a\":\"é\"}";
        assertDoesNotThrow(() -> Webhook.verifyWebhookSignature(body, sign(body.getBytes(StandardCharsets.UTF_8), t), SECRET));
    }

    @Test
    void toleranceMustBeNonNegative() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class,
                () -> Webhook.verifyWebhookSignature(body, sign(body, 1000), SECRET, -1, 1000L));
    }

    @Test
    void toleranceZero() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        String h = sign(body, 1000);
        assertDoesNotThrow(() -> Webhook.verifyWebhookSignature(body, h, SECRET, 0, 1000L));
        assertEquals("expired", code(() -> Webhook.verifyWebhookSignature(body, h, SECRET, 0, 1001L)));
    }

    @Test
    void nullHeaderMalformed() {
        assertEquals("malformed_header", code(() -> Webhook.verifyWebhookSignature(new byte[0], null, SECRET, 300, 1L)));
    }

    @Test
    void nullBodyOrSecretIsArgumentError() {
        assertThrows(IllegalArgumentException.class,
                () -> Webhook.verifyWebhookSignature((byte[]) null, "t=1,v1=" + "0".repeat(64), SECRET, 300, 1L));
        assertThrows(IllegalArgumentException.class,
                () -> Webhook.verifyWebhookSignature(new byte[0], "t=1,v1=" + "0".repeat(64), null, 300, 1L));
    }

    @Test
    void unicodeDigitsInTMalformed() {
        assertEquals("malformed_header", code(() -> Webhook.verifyWebhookSignature(new byte[] {'{', '}'},
                "t=١٢,v1=" + "0".repeat(64), SECRET, 300, 1L)));
    }

    @Test
    void trailingCommaMalformed() {
        assertEquals("malformed_header", code(() -> Webhook.verifyWebhookSignature(new byte[0],
                "t=1,v1=" + "0".repeat(64) + ",", SECRET, 300, 1L)));
    }

    @Test
    void loneSurrogateStringBodyMatchesNodeReplacementSemantics() {
        // Node's Buffer.from(str, 'utf8') turns a lone surrogate into U+FFFD; so do we.
        String body = "a\ud800b";
        assertDoesNotThrow(() -> Webhook.verifyWebhookSignature(body,
                sign("a�b".getBytes(StandardCharsets.UTF_8), 7), SECRET, 300, 7L));
        assertEquals("bad_signature", code(() -> Webhook.verifyWebhookSignature(body,
                sign("a?b".getBytes(StandardCharsets.UTF_8), 7), SECRET, 300, 7L)));
    }

    @Test
    void anyOfSeveralV1Passes() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        String good = sign(body, 5).split("v1=")[1];
        assertDoesNotThrow(() -> Webhook.verifyWebhookSignature(body, "t=5,v1=" + "0".repeat(64) + ",v1=" + good,
                SECRET, 300, 5L));
    }
}
