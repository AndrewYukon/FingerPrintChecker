package com.fpchecker.server;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fpchecker.server.events.Events;
import com.fpchecker.server.events.WebhookEvent;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * Compile check: the code below is the README's "Verifying an identification" and "Webhooks" snippets,
 * logic unchanged. The tests also assert the README still contains these exact lines, so the two cannot drift.
 */
class ReadmeSnippetsTest {
    // --- README: Verifying an identification (verbatim) ---
    static final Pattern EVENT_ID = Pattern.compile("^ev_[0-9A-HJKMNP-TV-Z]{20}$");
    static final Set<String> used = ConcurrentHashMap.newKeySet(); // use a shared store with expiry in production

    static boolean verifyEvent(FpChecker fp, String eventId) {
        if (eventId == null || !EVENT_ID.matcher(eventId).matches()) {
            return false;
        }
        JsonNode event;
        try {
            event = fp.getEvent(eventId);
        } catch (FpCheckerApiException e) {
            return false; // unknown event or an outage: do not accept
        }
        if (!eventId.equals(event.path("eventId").asText(null))) {
            return false; // the response must be for the event you asked about
        }
        try {
            Instant created = Instant.parse(event.path("createdAt").asText(""));
            long ageMs = Duration.between(created, Instant.now()).toMillis();
            if (Math.abs(ageMs) > Duration.ofMinutes(5).toMillis()) {
                return false; // too old (or from the future)
            }
        } catch (java.time.format.DateTimeParseException e) {
            return false; // missing or unparseable createdAt fails closed
        }
        return used.add(eventId); // each eventId counts once
    }

    // --- README: Webhooks (the framework's `request` replaced by a plain stand-in) ---
    interface Req {
        String getHeader(String name);
    }

    static WebhookEvent handle(Req request, byte[] rawBody) {
        Webhook.verifyWebhookSignature(rawBody, request.getHeader("FPC-Signature"), System.getenv("FPC_WEBHOOK_SECRET"));
        WebhookEvent event = Events.parseWebhookEvent(new String(rawBody, StandardCharsets.UTF_8)); // only after verifying
        return event;
    }

    @Test
    void verifyEventRejectsBadShapeWithoutNetwork() {
        assertFalse(verifyEvent(null, "nope"));
        assertFalse(verifyEvent(null, null));
    }

    @Test
    void readmeContainsTheSnippetsVerbatim() throws Exception {
        String readme = new String(Files.readAllBytes(Paths.get("README.md")), StandardCharsets.UTF_8);
        for (String line : new String[] {
            "static final Pattern EVENT_ID = Pattern.compile(\"^ev_[0-9A-HJKMNP-TV-Z]{20}$\");",
            "static boolean verifyEvent(FpChecker fp, String eventId) {",
            "return used.add(eventId); // each eventId counts once",
            "Webhook.verifyWebhookSignature(rawBody, request.getHeader(\"FPC-Signature\"), System.getenv(\"FPC_WEBHOOK_SECRET\"));",
            "WebhookEvent event = Events.parseWebhookEvent(new String(rawBody, StandardCharsets.UTF_8)); // only after verifying",
        }) {
            assertTrue(readme.contains(line), line);
        }
    }
}
