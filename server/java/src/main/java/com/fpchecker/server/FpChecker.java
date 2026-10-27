package com.fpchecker.server;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.json.JsonWriteFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpTimeoutException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Server client for the FpChecker API. The secret key goes only in the {@code X-Secret-Key} header. */
public final class FpChecker {
    public static final String DEFAULT_BASE_URL = "https://api.fpchecker.com";

    private static final int MAX_RETRIES = 2;
    private static final double MAX_DELAY_SECONDS = 10.0;
    private static final Set<String> LOOPBACK = Set.of("localhost", "127.0.0.1", "[::1]", "::1");
    private static final String USER_AGENT = "fpchecker-java/0.1.0";
    private static final Pattern RETRY_AFTER = Pattern.compile("[0-9]{1,9}");
    private static final ObjectMapper MAPPER = new ObjectMapper(
            JsonFactory.builder().enable(JsonWriteFeature.ESCAPE_NON_ASCII).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private final String secretKey;
    private final String publishableKey;
    private final String baseUrl;
    private final Duration timeout;
    private final Transport transport;
    private final Sleeper sleeper;

    /** Client with the default base URL and a 10 second timeout. */
    public FpChecker(String secretKey) {
        this(builder(secretKey));
    }

    private FpChecker(Builder b) {
        this(validated(b), new HttpTransport(b.timeout), Sleeper.REAL);
    }

    /** Test seam: inject a transport and sleeper. Not public, so callers cannot bypass the redirect refusal. */
    FpChecker(Builder b, Transport transport, Sleeper sleeper) {
        validated(b);
        this.secretKey = b.secretKey;
        this.publishableKey = b.publishableKey;
        this.baseUrl = validateBaseUrl(b.baseUrl);
        this.timeout = b.timeout;
        this.transport = transport;
        this.sleeper = sleeper;
    }

    public static Builder builder(String secretKey) {
        return new Builder(secretKey);
    }

    @Override
    public String toString() {
        return "FpChecker(baseUrl=" + baseUrl + ")";
    }

    /** Fluent configuration. Validation happens in {@link #build()}. */
    public static final class Builder {
        private final String secretKey;
        private String publishableKey;
        private String baseUrl = DEFAULT_BASE_URL;
        private Duration timeout = Duration.ofSeconds(10);

        private Builder(String secretKey) {
            this.secretKey = secretKey;
        }

        public Builder publishableKey(String publishableKey) {
            this.publishableKey = publishableKey;
            return this;
        }

        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        /** Must be positive. */
        public Builder timeout(Duration timeout) {
            checkTimeout(timeout);
            this.timeout = timeout;
            return this;
        }

        public FpChecker build() {
            return new FpChecker(this);
        }

        @Override
        public String toString() {
            return "FpChecker.Builder";
        }
    }

    // --- validation ---

    private static Builder validated(Builder b) {
        if (b.secretKey == null || b.secretKey.isEmpty()) {
            throw new IllegalArgumentException("FpChecker: secretKey is required");
        }
        checkHeaderValue("secretKey", b.secretKey);
        if (b.publishableKey != null) {
            if (b.publishableKey.isEmpty()) {
                throw new IllegalArgumentException("FpChecker: publishableKey must be a non-empty string");
            }
            checkHeaderValue("publishableKey", b.publishableKey);
        }
        checkTimeout(b.timeout);
        validateBaseUrl(b.baseUrl);
        return b;
    }

    private static void checkTimeout(Duration timeout) {
        if (timeout == null || timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("FpChecker: timeout must be a positive duration");
        }
    }

    private static void checkHeaderValue(String name, String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c >= 0x7F) {
                throw new IllegalArgumentException(
                        "FpChecker: " + name + " must be printable ASCII (no control characters)");
            }
        }
    }

    private static String validateBaseUrl(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("FpChecker: baseUrl must be a string");
        }
        URI u;
        try {
            u = new URI(raw);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("FpChecker: baseUrl is not a valid URL");
        }
        String host = u.getHost();
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("FpChecker: baseUrl is not a valid URL");
        }
        boolean loopback = LOOPBACK.contains(host.toLowerCase(Locale.ROOT));
        if (!scheme.equals("https") && !(scheme.equals("http") && loopback)) {
            throw new IllegalArgumentException(
                    "FpChecker: baseUrl must be https (http only for localhost, 127.0.0.1, [::1])");
        }
        int end = raw.length();
        while (end > 0 && raw.charAt(end - 1) == '/') {
            end--;
        }
        return raw.substring(0, end);
    }

    // --- operations (method name = operationId) ---

    public JsonNode createIntent(Object body) {
        return call("POST", "/v2/intents", null, body, false, true);
    }

    public JsonNode getChallenge(Map<String, ?> query) {
        return call("GET", "/v2/challenge", query, null, true, true);
    }

    public JsonNode identify(Object body) {
        return call("POST", "/v2/identify", null, body, true, true);
    }

    public JsonNode checkEligibility(Object body) {
        return call("POST", "/v1/eligibility", null, body, false, true);
    }

    public JsonNode releaseEligibility(Object body) {
        return call("POST", "/v1/eligibility/release", null, body, false, true);
    }

    /**
     * Classify a request your backend received. Not charged, writes no event. Send {@code url} as the visitor
     * requested it (original host and scheme).
     */
    public JsonNode botCheck(String method, String url, String ip, Map<String, String> headers) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("method", method);
        body.put("url", url);
        body.put("ip", ip);
        body.set("headers", MAPPER.valueToTree(BotHeaders.filter(headers)));
        return call("POST", "/v1/bot-check", null, body, false, true);
    }

    public JsonNode checkQuota(Object body) {
        return call("POST", "/v1/quota", null, body, false, true);
    }

    public JsonNode bindSubject(Object body) {
        return call("POST", "/v1/subjects/bind", null, body, false, true);
    }

    public JsonNode relateSubjects(Object body) {
        return call("POST", "/v1/subjects/relation", null, body, false, true);
    }

    public JsonNode sendFeedback(Object body) {
        return call("POST", "/v1/feedback", null, body, false, true);
    }

    public JsonNode getClaimFlags() {
        return getClaimFlags(null);
    }

    public JsonNode getClaimFlags(Map<String, ?> query) {
        return call("GET", "/v1/claims/flags", query, null, false, true);
    }

    public JsonNode searchEvents() {
        return searchEvents(null);
    }

    public JsonNode searchEvents(Map<String, ?> query) {
        return call("GET", "/v1/events", query, null, false, true);
    }

    public JsonNode getEvent(String eventId) {
        return call("GET", "/v1/events/" + pathId(eventId), null, null, false, true);
    }

    public JsonNode updateEvent(String eventId, Object body) {
        return call("PATCH", "/v1/events/" + pathId(eventId), null, body, false, true);
    }

    public JsonNode getVisitor(String visitorId) {
        return call("GET", "/v1/visitors/" + pathId(visitorId), null, null, false, true);
    }

    public JsonNode deleteVisitor(String visitorId) {
        return call("DELETE", "/v1/visitors/" + pathId(visitorId), null, null, false, true);
    }

    public JsonNode getHealth() {
        return call("GET", "/health", null, null, false, false);
    }

    public JsonNode getStatus() {
        return call("GET", "/status", null, null, false, false);
    }

    // --- encoding ---

    /** quote(value, safe="") for a path segment; ids that could change the route are refused. */
    private static String pathId(String id) {
        if (id == null || id.isEmpty() || id.equals(".") || id.equals("..")) {
            throw new IllegalArgumentException("FpChecker: id must be a non-empty string and not '.' or '..'");
        }
        return encode(id, false);
    }

    /** Python quote / quote_plus with safe="": unreserved is A-Za-z0-9 and _.-~ */
    static String encode(String value, boolean plus) {
        StringBuilder sb = new StringBuilder();
        for (byte raw : value.getBytes(StandardCharsets.UTF_8)) {
            int c = raw & 0xFF;
            boolean unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '_' || c == '.' || c == '-' || c == '~';
            if (unreserved) {
                sb.append((char) c);
            } else if (plus && c == ' ') {
                sb.append('+');
            } else {
                sb.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16)))
                        .append(Character.toUpperCase(Character.forDigit(c & 0xF, 16)));
            }
        }
        return sb.toString();
    }

    static String queryString(Map<String, ?> query) {
        if (query == null || query.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, ?> e : query.entrySet()) {
            Object v = e.getValue();
            if (v == null) {
                continue;
            }
            sb.append(sb.length() == 0 ? '?' : '&')
                    .append(encode(String.valueOf(e.getKey()), true))
                    .append('=')
                    .append(encode(String.valueOf(v), true));
        }
        return sb.toString();
    }

    // --- response parsing ---

    private static JsonNode parseJson(byte[] raw) {
        if (raw == null || raw.length == 0) {
            return null;
        }
        try {
            JsonNode n = MAPPER.readTree(raw);
            return n == null || n.isNull() || n.isMissingNode() ? null : n;
        } catch (IOException e) {
            return null;
        }
    }

    private static String errorCode(JsonNode body) {
        if (body == null || !body.isObject()) {
            return null;
        }
        JsonNode code = body.get("error");
        if (code == null || code.isNull()) {
            code = body.get("reason");
        }
        return code != null && code.isTextual() ? code.asText() : null;
    }

    private static Integer parseRetryAfter(String value) {
        if (value == null) {
            return null;
        }
        String v = value.trim();
        return RETRY_AFTER.matcher(v).matches() ? Integer.valueOf(v) : null;
    }

    private static boolean isTimeout(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof HttpTimeoutException || c instanceof SocketTimeoutException) {
                return true;
            }
            if (c.getCause() == c) {
                break;
            }
        }
        return false;
    }

    // --- transport ---

    private JsonNode call(String method, String path, Map<String, ?> query, Object body, boolean publishable,
            boolean auth) {
        String url = baseUrl + path + queryString(query);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Accept", "application/json");
        headers.put("User-Agent", USER_AGENT);
        if (publishable) {
            if (publishableKey == null) {
                throw new IllegalStateException("FpChecker: publishableKey is required for this operation");
            }
            headers.put("X-Publishable-Key", publishableKey);
        } else if (auth) {
            headers.put("X-Secret-Key", secretKey);
        }
        byte[] data = null;
        if (body != null) {
            try {
                data = MAPPER.writeValueAsBytes(body);
            } catch (JsonProcessingException e) {
                throw new IllegalArgumentException("FpChecker: body is not JSON-serializable");
            }
            headers.put("Content-Type", "application/json");
        }
        int maxRetries = method.equals("GET") ? MAX_RETRIES : 0;

        int attempt = 0;
        while (true) {
            Transport.Response res = null;
            Throwable failure = null;
            try {
                res = transport.send(new Transport.Request(method, url, headers, data, timeout));
                if (res.status >= 300 && res.status < 400) {
                    // A redirect would forward X-Secret-Key to another origin: never follow, never read Location.
                    failure = new IOException("redirect refused (HTTP " + res.status + ")");
                }
            } catch (IOException e) {
                failure = e;
            } catch (RuntimeException e) {
                // A transport must report failures as IOException; never let an unchecked one escape raw.
                failure = new IOException("request failed: " + e.getClass().getSimpleName());
            }

            if (failure != null) {
                if (attempt < maxRetries) {
                    pause(Math.min(0.5 * (1 << attempt), MAX_DELAY_SECONDS));
                    attempt++;
                    continue;
                }
                throw new FpCheckerApiException(0, isTimeout(failure) ? "timeout" : "network_error", null, null,
                        failure);
            }

            JsonNode parsed = parseJson(res.body);
            if (res.status >= 200 && res.status < 300) {
                return parsed != null ? parsed : MAPPER.createObjectNode();
            }

            Integer retryAfter = parseRetryAfter(res.headers == null ? null : res.headers.get("Retry-After"));
            if ((res.status == 429 || res.status >= 500) && attempt < maxRetries) {
                double wait = retryAfter != null ? retryAfter : 0.5 * (1 << attempt);
                pause(Math.min(wait, MAX_DELAY_SECONDS));
                attempt++;
                continue;
            }
            throw new FpCheckerApiException(res.status, errorCode(parsed), retryAfter, parsed);
        }
    }

    private void pause(double seconds) {
        try {
            sleeper.sleep(Duration.ofMillis((long) (seconds * 1000)));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new FpCheckerApiException(0, "network_error", null, null, e);
        }
    }
}
