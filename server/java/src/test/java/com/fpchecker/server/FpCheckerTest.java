package com.fpchecker.server;

import static com.fpchecker.server.FakeTransport.header;
import static com.fpchecker.server.FakeTransport.resp;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class FpCheckerTest {
    static final String SK = "sk_test_123";
    static final String PK = "pk_test_9";
    static final ObjectMapper M = new ObjectMapper();

    private final List<Duration> sleeps = new ArrayList<>();

    private FpChecker mk(FakeTransport t) {
        return new FpChecker(FpChecker.builder(SK), t, sleeps::add);
    }

    private FpChecker mk(FakeTransport t, FpChecker.Builder b) {
        return new FpChecker(b, t, sleeps::add);
    }

    private static JsonNode json(String s) {
        try {
            return M.readTree(s);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    // --- surface ---

    static final class Op {
        final String id;
        final String method;
        final String path;
        final List<JsonNode> params;
        final boolean hasBody;
        final List<String> sec;

        Op(String id, String method, String path, List<JsonNode> params, boolean hasBody, List<String> sec) {
            this.id = id;
            this.method = method;
            this.path = path;
            this.params = params;
            this.hasBody = hasBody;
            this.sec = sec;
        }

        @Override
        public String toString() {
            return id;
        }
    }

    static JsonNode spec() {
        try {
            return M.readTree(Files.readAllBytes(Path.of("../../openapi/fpchecker-api.json")));
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    static JsonNode deref(JsonNode root, JsonNode p) {
        if (!p.has("$ref")) {
            return p;
        }
        JsonNode o = root;
        String[] parts = p.get("$ref").asText().split("/");
        for (int i = 1; i < parts.length; i++) {
            o = o.get(parts[i]);
        }
        return o;
    }

    static List<Op> operations() {
        JsonNode root = spec();
        List<Op> ops = new ArrayList<>();
        root.get("paths").fields().forEachRemaining(pe -> {
            JsonNode item = pe.getValue();
            item.fields().forEachRemaining(me -> {
                JsonNode op = me.getValue();
                if (!op.isObject() || !op.has("operationId")) {
                    return;
                }
                List<JsonNode> params = new ArrayList<>();
                for (JsonNode p : item.path("parameters")) {
                    params.add(deref(root, p));
                }
                for (JsonNode p : op.path("parameters")) {
                    params.add(deref(root, p));
                }
                JsonNode secNode = op.has("security") ? op.get("security") : root.path("security");
                List<String> sec = new ArrayList<>();
                for (JsonNode s : secNode) {
                    s.fieldNames().forEachRemaining(sec::add);
                }
                if (sec.contains("managementKey")) {
                    return; // the account-level management API is not part of this SDK
                }
                ops.add(new Op(op.get("operationId").asText(), me.getKey().toUpperCase(), pe.getKey(), params,
                        op.has("requestBody"), sec));
            });
        });
        return ops;
    }

    static Stream<Op> opsStream() {
        return operations().stream();
    }

    static Method find(String name, int argc) {
        for (Method m : FpChecker.class.getMethods()) {
            if (m.getName().equals(name) && m.getParameterCount() == argc) {
                return m;
            }
        }
        return null;
    }

    @Test
    void opTableComplete() {
        assertEquals(18, operations().size());
    }

    @Test
    void everyOperationIdHasMethod() {
        List<String> missing = operations().stream()
                .filter(o -> Stream.of(FpChecker.class.getMethods()).noneMatch(m -> m.getName().equals(o.id)))
                .map(o -> o.id)
                .collect(Collectors.toList());
        assertEquals(List.of(), missing);
    }

    @ParameterizedTest
    @MethodSource("opsStream")
    void operationTable(Op op) throws Exception {
        FakeTransport t = new FakeTransport(resp(200, "{\"ok\":true}"));
        FpChecker client = mk(t, FpChecker.builder(SK).publishableKey(PK));
        List<JsonNode> pathParams = op.params.stream().filter(p -> p.get("in").asText().equals("path"))
                .collect(Collectors.toList());
        boolean hasQuery = op.params.stream().anyMatch(p -> p.get("in").asText().equals("query"));
        List<Object> args = new ArrayList<>();
        for (int i = 0; i < pathParams.size(); i++) {
            args.add("id/" + i + " x");
        }
        if (op.hasBody) {
            args.add(Map.of("a", 1));
        } else if (hasQuery) {
            args.add(Map.of("intent", "i"));
        }
        JsonNode out;
        if (op.id.equals("botCheck")) { // four explicit arguments by design
            out = client.botCheck("GET", "https://x.test/", "1.1.1.1", Map.of());
        } else {
            Method m = find(op.id, args.size());
            assertNotNull(m, "no method " + op.id + "/" + args.size());
            try {
                out = (JsonNode) m.invoke(client, args.toArray());
            } catch (InvocationTargetException e) {
                throw (Exception) e.getCause();
            }
        }
        assertEquals(json("{\"ok\":true}"), out);
        Transport.Request req = t.calls.get(0);
        String expected = op.path;
        for (int i = 0; i < pathParams.size(); i++) {
            expected = expected.replace("{" + pathParams.get(i).get("name").asText() + "}",
                    "id%2F" + i + "%20x");
        }
        assertEquals(expected, URI.create(req.url).getRawPath());
        assertEquals(op.method, req.method);
        assertEquals(op.sec.contains("secretKey"), header(req, "X-Secret-Key") != null);
        assertEquals(op.sec.contains("publishableKey"), header(req, "X-Publishable-Key") != null);
        if (op.sec.contains("secretKey")) {
            assertEquals(SK, header(req, "X-Secret-Key"));
        }
        if (op.sec.contains("publishableKey")) {
            assertEquals(PK, header(req, "X-Publishable-Key"));
        }
        assertFalse(req.url.contains("sk_test") || req.url.contains("pk_test"));
    }

    @Test
    void requiresSecretKey() {
        assertThrows(IllegalArgumentException.class, () -> new FpChecker(""));
        assertThrows(IllegalArgumentException.class, () -> new FpChecker(null));
        assertThrows(IllegalArgumentException.class, () -> FpChecker.builder(null).build());
    }

    @Test
    void reprAndStrHideKey() {
        assertFalse(new FpChecker(SK).toString().contains(SK));
        assertFalse(FpChecker.builder(SK).publishableKey(PK).build().toString().contains(PK));
        assertFalse(FpChecker.builder(SK).toString().contains(SK));
    }

    // --- requests ---

    @Test
    void queryEncodingAndBaseUrl() {
        FakeTransport t = new FakeTransport(resp(200, "{}"));
        FpChecker c = mk(t, FpChecker.builder(SK).baseUrl("https://x.test/"));
        Map<String, Object> q = new LinkedHashMap<>();
        q.put("visitorId", "v 1");
        q.put("bot", true);
        q.put("off", false);
        q.put("limit", 5);
        q.put("linkedId", null);
        c.searchEvents(q);
        assertEquals("https://x.test/v1/events?visitorId=v+1&bot=true&off=false&limit=5", t.calls.get(0).url);
    }

    @Test
    void queryEncodingMatchesQuotePlus() {
        assertEquals("a%2Fb%3Fc%26d%3De+f~%2A-_.%C3%A9", FpChecker.encode("a/b?c&d=e f~*-_.\u00e9", true));
        assertEquals("~", FpChecker.encode("~", true));
        assertEquals("%2A", FpChecker.encode("*", true));
        assertEquals("%20", FpChecker.encode(" ", false));
    }

    @Test
    void pathParamEncoded() {
        FakeTransport t = new FakeTransport(resp(200, "{}"));
        mk(t).getVisitor("a/b");
        assertEquals("https://api.fpchecker.com/v1/visitors/a%2Fb", t.calls.get(0).url);
    }

    @Test
    void pathIdIsPercentEncoded() {
        FakeTransport t = new FakeTransport(resp(200, "{}"));
        mk(t).getEvent("a/b?c");
        assertEquals("/v1/events/a%2Fb%3Fc", URI.create(t.calls.get(0).url).getRawPath());
        assertNull(URI.create(t.calls.get(0).url).getRawQuery());
    }

    @Test
    void pathIdThatCouldChangeTheRouteIsRejected() {
        FakeTransport t = new FakeTransport();
        FpChecker c = mk(t);
        for (String bad : new String[] {"", ".", "..", null}) {
            assertThrows(IllegalArgumentException.class, () -> c.getEvent(bad));
            assertThrows(IllegalArgumentException.class, () -> c.getVisitor(bad));
            assertThrows(IllegalArgumentException.class, () -> c.deleteVisitor(bad));
            assertThrows(IllegalArgumentException.class, () -> c.updateEvent(bad, Map.of()));
        }
        assertTrue(t.calls.isEmpty());
    }

    @Test
    void postSendsJson() {
        FakeTransport t = new FakeTransport(resp(200, "{\"ok\":true}"));
        mk(t).checkEligibility(Map.of("visitorId", "v_1"));
        Transport.Request r = t.calls.get(0);
        assertEquals("POST", r.method);
        assertEquals("{\"visitorId\":\"v_1\"}", new String(r.body, StandardCharsets.UTF_8));
        assertEquals("application/json", header(r, "Content-Type"));
        assertEquals("fpchecker-java/0.1.0", header(r, "User-Agent"));
    }

    @Test
    void nonAsciiBodyIsEscaped() {
        FakeTransport t = new FakeTransport(resp(200, "{}"));
        mk(t).checkEligibility(Map.of("n", "\u00e9"));
        assertEquals("{\"n\":\"\\u00E9\"}", new String(t.calls.get(0).body, StandardCharsets.UTF_8));
    }

    @Test
    void secretNotSentOnPublishableOpsAndViceVersa() {
        FakeTransport t = new FakeTransport(resp(200, "{}"), resp(200, "{}"));
        FpChecker c = mk(t, FpChecker.builder(SK).publishableKey(PK));
        c.identify(Map.of());
        c.getHealth();
        assertNull(header(t.calls.get(0), "X-Secret-Key"));
        assertEquals(PK, header(t.calls.get(0), "X-Publishable-Key"));
        assertNull(header(t.calls.get(1), "X-Secret-Key"));
        assertNull(header(t.calls.get(1), "X-Publishable-Key"));
    }

    @Test
    void publishableOpsNeedKey() {
        FakeTransport t = new FakeTransport();
        FpChecker c = mk(t);
        assertThrows(IllegalStateException.class, () -> c.identify(Map.of()));
        assertThrows(IllegalStateException.class, () -> c.getChallenge(Map.of("intent", "i")));
        assertTrue(t.calls.isEmpty());
    }

    @Test
    void twoXxOkFalseReturnedAsData() {
        FakeTransport t = new FakeTransport(resp(200, "{\"ok\":false,\"reason\":\"quota_exhausted\"}"));
        assertEquals(json("{\"ok\":false,\"reason\":\"quota_exhausted\"}"), mk(t).checkQuota(Map.of()));
    }

    @Test
    void twoXxEmptyOrNonJsonIsEmptyDict() {
        FakeTransport t = new FakeTransport(resp(204), resp(200, "<html>"));
        FpChecker c = mk(t);
        assertEquals(json("{}"), c.getHealth());
        assertEquals(json("{}"), c.getHealth());
    }

    @Test
    void htmlBodyOn200ReturnsEmptyObject() {
        FakeTransport t = new FakeTransport(resp(200, "<!doctype html><html><body>502 Bad Gateway</body></html>"));
        JsonNode out = mk(t).getStatus();
        assertTrue(out.isObject());
        assertEquals(0, out.size());
    }

    @Test
    void trailingGarbageAfterJsonIsNotJson() {
        FakeTransport t = new FakeTransport(resp(200, "{\"a\":1} junk"));
        assertEquals(json("{}"), mk(t).getStatus());
    }

    // --- errors ---

    @Test
    void non2xxErrorCode() {
        FakeTransport t = new FakeTransport(resp(403, "{\"ok\":false,\"error\":\"forbidden\"}"));
        FpCheckerApiException e = assertThrows(FpCheckerApiException.class, () -> mk(t).getEvent("e"));
        assertEquals(403, e.status());
        assertEquals("forbidden", e.code());
        assertNull(e.retryAfter());
        assertEquals(json("{\"ok\":false,\"error\":\"forbidden\"}"), e.body());
    }

    @Test
    void codeFallsBackToReasonThenNone() {
        FakeTransport t = new FakeTransport(resp(400, "{\"ok\":false,\"reason\":\"bad_input\"}"),
                resp(502, "<html>"));
        FpChecker c = mk(t);
        assertEquals("bad_input", assertThrows(FpCheckerApiException.class, () -> c.updateEvent("e", Map.of())).code());
        FpCheckerApiException b = assertThrows(FpCheckerApiException.class, () -> c.createIntent(Map.of()));
        assertEquals(502, b.status());
        assertNull(b.code());
        assertNull(b.body());
    }

    @Test
    void errorNeverContainsSecret() {
        FakeTransport t = new FakeTransport(resp(401, "{\"error\":\"bad_key\"}"));
        FpChecker c = mk(t);
        FpCheckerApiException e = assertThrows(FpCheckerApiException.class, () -> c.getEvent("e"));
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        assertFalse((e.toString() + e.getMessage() + sw).contains(SK));
    }

    @Test
    void exceptionStringNeverContainsSecret() {
        for (Object failure : new Object[] {resp(401, "{\"error\":\"bad_key\"}"), new IOException("refused"),
                resp(302, "", "Location", "https://evil.test/x")}) {
            FakeTransport t = new FakeTransport(failure, failure, failure);
            FpChecker c = new FpChecker(FpChecker.builder("sk_test_secret"), t, sleeps::add);
            FpCheckerApiException ex = assertThrows(FpCheckerApiException.class, () -> c.getEvent("e"));
            assertFalse(ex.toString().contains("sk_test_secret"));
            assertFalse(c.toString().contains("sk_test_secret"));
        }
    }

    // --- retries ---

    @Test
    void getRetriedOn503WithRetryAfter() {
        FakeTransport t = new FakeTransport(resp(503, "{\"error\":\"u\"}", "Retry-After", "2"),
                resp(200, "{\"ok\":true}"));
        assertEquals(json("{\"ok\":true}"), mk(t).getVisitor("v"));
        assertEquals(2, t.calls.size());
        assertEquals(List.of(Duration.ofSeconds(2)), sleeps);
    }

    @Test
    void getGivesUpAfterTwoRetries() {
        FakeTransport t = new FakeTransport(resp(500, "{}"), resp(500, "{}"),
                resp(429, "{\"error\":\"rate\"}", "Retry-After", "1"));
        FpCheckerApiException e = assertThrows(FpCheckerApiException.class, () -> mk(t).getHealth());
        assertEquals(3, t.calls.size());
        assertEquals(429, e.status());
        assertEquals(1, e.retryAfter());
        assertEquals(List.of(Duration.ofMillis(500), Duration.ofSeconds(1)), sleeps);
    }

    @Test
    void retryAfterCapped() {
        FakeTransport t = new FakeTransport(resp(429, "{}", "Retry-After", "3600"), resp(200, "{}"));
        mk(t).getStatus();
        assertTrue(sleeps.get(0).compareTo(Duration.ofSeconds(10)) <= 0);
    }

    @Test
    void retryAfterOnlyDigits() {
        FakeTransport t = new FakeTransport(resp(503, "{}", "Retry-After", "1234567890"),
                resp(503, "{}", "Retry-After", "-5"), resp(503, "{}", "Retry-After", "Wed, 21 Oct 2026"));
        FpCheckerApiException e = assertThrows(FpCheckerApiException.class, () -> mk(t).getHealth());
        assertNull(e.retryAfter());
        assertEquals(List.of(Duration.ofMillis(500), Duration.ofSeconds(1)), sleeps);
    }

    @Test
    void noRetryOnOther4xx() {
        FakeTransport t = new FakeTransport(resp(404, "{\"error\":\"not_found\"}"));
        assertThrows(FpCheckerApiException.class, () -> mk(t).getEvent("x"));
        assertEquals(1, t.calls.size());
    }

    @ParameterizedTest
    @ValueSource(ints = {429, 503})
    void billedPostNeverRetried(int status) {
        FakeTransport t = new FakeTransport(resp(status, "{\"error\":\"x\"}", "Retry-After", "1"), resp(200, "{}"));
        assertThrows(FpCheckerApiException.class, () -> mk(t).checkEligibility(Map.of("visitorId", "v")));
        assertEquals(1, t.calls.size());
        assertTrue(sleeps.isEmpty());
    }

    @Test
    void patchDeleteNeverRetried() {
        FakeTransport a = new FakeTransport(resp(503, "{}"), resp(200, "{}"));
        assertThrows(FpCheckerApiException.class, () -> mk(a).updateEvent("e", Map.of()));
        FakeTransport b = new FakeTransport(resp(503, "{}"), resp(200, "{}"));
        assertThrows(FpCheckerApiException.class, () -> mk(b).deleteVisitor("v"));
        assertEquals(1, a.calls.size());
        assertEquals(1, b.calls.size());
    }

    // --- network ---

    @Test
    void networkErrorWrappedWithCause() {
        IOException cause = new IOException("refused");
        FakeTransport t = new FakeTransport(cause);
        FpCheckerApiException e = assertThrows(FpCheckerApiException.class, () -> mk(t).checkQuota(Map.of()));
        assertEquals(0, e.status());
        assertEquals("network_error", e.code());
        assertSame(cause, e.getCause());
        assertEquals(1, t.calls.size());
    }

    static Stream<IOException> timeouts() {
        return Stream.of(new HttpTimeoutException("t"), new SocketTimeoutException("t"),
                new IOException("wrapped", new SocketTimeoutException("t")));
    }

    @ParameterizedTest
    @MethodSource("timeouts")
    void timeoutsWrapped(IOException exc) {
        FakeTransport t = new FakeTransport(exc, exc, exc);
        FpCheckerApiException e = assertThrows(FpCheckerApiException.class, () -> mk(t).getHealth());
        assertEquals(0, e.status());
        assertEquals("timeout", e.code());
        assertSame(exc, e.getCause());
    }

    @Test
    void getRetriesNetworkFailuresAtMostTwice() {
        FakeTransport t = new FakeTransport(new IOException("a"), new IOException("b"), new IOException("c"),
                resp(200, "{}"));
        FpCheckerApiException e = assertThrows(FpCheckerApiException.class, () -> mk(t).getVisitor("v"));
        assertEquals(3, t.calls.size());
        assertEquals("network_error", e.code());
        FakeTransport t2 = new FakeTransport(new IOException("a"), resp(200, "{\"ok\":true}"));
        assertEquals(json("{\"ok\":true}"), mk(t2).getVisitor("v"));
    }

    @Test
    void nonGetNeverRetriesNetworkFailures() {
        List<java.util.function.Consumer<FpChecker>> calls = List.of(
                c -> c.updateEvent("e", Map.of()), c -> c.deleteVisitor("v"), c -> c.checkEligibility(Map.of()));
        for (java.util.function.Consumer<FpChecker> call : calls) {
            FakeTransport t = new FakeTransport(new IOException("x"), resp(200, "{}"));
            assertThrows(FpCheckerApiException.class, () -> call.accept(mk(t)));
            assertEquals(1, t.calls.size());
        }
    }

    // --- baseUrl ---

    @Test
    void baseUrlValidation() {
        for (String bad : new String[] {"http://api.example.com", "not a url", "ftp://x.test", "https://", "",
                null, "http://localhost@evil.com"}) {
            assertThrows(IllegalArgumentException.class, () -> FpChecker.builder("sk").baseUrl(bad).build(), bad);
        }
        for (String ok : new String[] {"http://localhost:8787", "http://127.0.0.1:1", "http://[::1]:2",
                "https://x.test", "HTTP://LOCALHOST:1"}) {
            assertDoesNotThrow(() -> FpChecker.builder("sk").baseUrl(ok).build(), ok);
        }
    }

    @Test
    void baseUrlTrailingSlashesStripped() {
        FakeTransport t = new FakeTransport(resp(200, "{}"));
        mk(t, FpChecker.builder(SK).baseUrl("https://x.test///")).getHealth();
        assertEquals("https://x.test/health", t.calls.get(0).url);
    }

    // --- redirects ---

    @Test
    void redirectToOtherHostIsNeverFollowed() {
        FakeTransport t = new FakeTransport(resp(302, "", "Location", "https://evil.test/x"), resp(200, "{}"));
        FpCheckerApiException e = assertThrows(FpCheckerApiException.class, () -> mk(t).checkQuota(Map.of()));
        assertEquals(1, t.calls.size());
        assertEquals("api.fpchecker.com", URI.create(t.calls.get(0).url).getHost());
        assertEquals(0, e.status());
        assertEquals("network_error", e.code());
    }

    @Test
    void redirectOnGetIsRetriedLikeANetworkFailureButNeverFollowed() {
        FakeTransport t = new FakeTransport(resp(301, "", "Location", "https://evil.test/x"),
                resp(308, "", "Location", "https://evil.test/x"), resp(307, "", "Location", "https://evil.test/x"));
        FpCheckerApiException e = assertThrows(FpCheckerApiException.class, () -> mk(t).getHealth());
        assertEquals(3, t.calls.size());
        assertTrue(t.calls.stream().allMatch(r -> URI.create(r.url).getHost().equals("api.fpchecker.com")));
        assertEquals("network_error", e.code());
    }

    // --- real sockets ---

    private static HttpServer server(com.sun.net.httpserver.HttpHandler h) throws IOException {
        HttpServer s = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        s.createContext("/", h);
        s.start();
        return s;
    }

    @ParameterizedTest
    @ValueSource(ints = {301, 302, 307, 308})
    void realRedirectsNotFollowed(int code) throws Exception {
        List<String> seen = new CopyOnWriteArrayList<>();
        HttpServer target = server(ex -> {
            seen.add(ex.getRequestHeaders().getFirst("X-Secret-Key"));
            ex.sendResponseHeaders(200, -1);
            ex.close();
        });
        HttpServer red = server(ex -> {
            ex.getResponseHeaders().add("Location", "http://127.0.0.1:" + target.getAddress().getPort() + "/x");
            ex.sendResponseHeaders(code, -1);
            ex.close();
        });
        try {
            String base = "http://127.0.0.1:" + red.getAddress().getPort();
            FpChecker c = FpChecker.builder(SK).baseUrl(base).timeout(Duration.ofSeconds(5)).build();
            FpCheckerApiException a = assertThrows(FpCheckerApiException.class, () -> c.checkQuota(Map.of()));
            assertEquals("network_error", a.code());
            FpCheckerApiException b = assertThrows(FpCheckerApiException.class, c::getHealth);
            assertEquals(0, b.status());
            assertEquals("network_error", b.code());
            assertTrue(seen.isEmpty());
        } finally {
            red.stop(0);
            target.stop(0);
        }
    }

    @Test
    void realRoundtripSendsSecretHeader() throws Exception {
        List<String> got = new CopyOnWriteArrayList<>();
        HttpServer s = server(ex -> {
            got.add(ex.getRequestHeaders().getFirst("X-Secret-Key"));
            got.add(ex.getRequestURI().getRawPath());
            got.add(ex.getRequestHeaders().getFirst("User-Agent"));
            byte[] body = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(body);
            }
        });
        try {
            FpChecker c = FpChecker.builder(SK).baseUrl("http://127.0.0.1:" + s.getAddress().getPort()).build();
            assertEquals(json("{\"ok\":true}"), c.getEvent("e 1"));
            assertEquals(SK, got.get(0));
            assertEquals("/v1/events/e%201", got.get(1));
            assertFalse(got.get(1).contains(SK));
            assertEquals("fpchecker-java/0.1.0", got.get(2));
        } finally {
            s.stop(0);
        }
    }

    @Test
    void realRoundtripPostBody() throws Exception {
        List<String> got = new CopyOnWriteArrayList<>();
        HttpServer s = server(ex -> {
            got.add(ex.getRequestMethod());
            got.add(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            ex.sendResponseHeaders(204, -1);
            ex.close();
        });
        try {
            FpChecker c = FpChecker.builder(SK).baseUrl("http://127.0.0.1:" + s.getAddress().getPort()).build();
            assertEquals(json("{}"), c.updateEvent("e", Map.of("k", "v")));
            assertEquals(List.of("PATCH", "{\"k\":\"v\"}"), got);
        } finally {
            s.stop(0);
        }
    }

    private static ServerSocket rawServer(byte[] payload) throws IOException {
        ServerSocket ss = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread th = new Thread(() -> {
            while (!ss.isClosed()) {
                try (Socket s = ss.accept()) {
                    byte[] buf = new byte[65536];
                    s.getInputStream().read(buf);
                    s.getOutputStream().write(payload);
                    s.getOutputStream().flush();
                } catch (IOException e) {
                    // closed
                }
            }
        });
        th.setDaemon(true);
        th.start();
        return ss;
    }

    @ParameterizedTest
    @ValueSource(strings = {"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{", "garbage\r\n\r\n",
            "HTTP/1.1 500 X\r\nContent-Length: 100\r\n\r\n{"})
    void truncatedOrGarbageResponsesWrappedAndGetRetried(String payload) throws Exception {
        try (ServerSocket ss = rawServer(payload.getBytes(StandardCharsets.UTF_8))) {
            FpChecker c = new FpChecker(
                    FpChecker.builder(SK).baseUrl("http://127.0.0.1:" + ss.getLocalPort()).timeout(Duration.ofSeconds(5)),
                    new HttpTransport(Duration.ofSeconds(5)), sleeps::add);
            FpCheckerApiException e = assertThrows(FpCheckerApiException.class, c::getHealth);
            assertEquals(0, e.status());
            assertEquals("network_error", e.code());
            assertEquals(2, sleeps.size());
            e = assertThrows(FpCheckerApiException.class, () -> c.checkQuota(Map.of()));
            assertEquals("network_error", e.code());
            assertEquals(2, sleeps.size());
        }
    }

    @Test
    void realTimeoutMapsToTimeout() throws Exception {
        try (ServerSocket ss = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            Thread th = new Thread(() -> {
                try (Socket s = ss.accept()) {
                    Thread.sleep(2000); // never answer
                } catch (Exception e) {
                    // closed
                }
            });
            th.setDaemon(true);
            th.start();
            FpChecker c = new FpChecker(
                    FpChecker.builder(SK).baseUrl("http://127.0.0.1:" + ss.getLocalPort()).timeout(Duration.ofMillis(300)),
                    new HttpTransport(Duration.ofMillis(300)), sleeps::add);
            FpCheckerApiException e = assertThrows(FpCheckerApiException.class, () -> c.checkQuota(Map.of()));
            assertEquals("timeout", e.code());
        }
    }

    // --- config validation ---

    @Test
    void invalidTimeoutRejectedAtConstruction() {
        for (Duration bad : new Duration[] {Duration.ZERO, Duration.ofSeconds(-1), Duration.ofMillis(-1), null}) {
            assertThrows(IllegalArgumentException.class, () -> FpChecker.builder(SK).timeout(bad).build());
        }
        assertDoesNotThrow(() -> FpChecker.builder(SK).timeout(Duration.ofMillis(1)).build());
    }

    @ParameterizedTest
    @ValueSource(strings = {"sk\r\nX: y", "sk\n", "sk\u0000", "sk\u007f", "s k\t", "sk\u00e9"})
    void keysWithControlCharsRejected(String bad) {
        assertThrows(IllegalArgumentException.class, () -> new FpChecker(bad));
        assertThrows(IllegalArgumentException.class, () -> FpChecker.builder(SK).publishableKey(bad).build());
    }

    @Test
    void emptyPublishableKeyRejectedButNullOk() {
        assertDoesNotThrow(() -> FpChecker.builder(SK).publishableKey(null).build());
        assertThrows(IllegalArgumentException.class, () -> FpChecker.builder(SK).publishableKey("").build());
    }

    @Test
    void mobileSignalFiltersAreForwarded() {
        FakeTransport t = new FakeTransport(resp(200, "{}"));
        Map<String, Object> q = new LinkedHashMap<>();
        q.put("rooted", true);
        q.put("hooked", false);
        q.put("emulator", true);
        q.put("mitm", true);
        q.put("locationSpoofed", false);
        q.put("clonedApp", true);
        mk(t).searchEvents(q);
        assertEquals("https://api.fpchecker.com/v1/events?rooted=true&hooked=false&emulator=true&mitm=true"
                + "&locationSpoofed=false&clonedApp=true", t.calls.get(0).url);
    }

    @Test
    void botCheckBodyShape() throws Exception {
        FakeTransport t = new FakeTransport(resp(200, "{\"bot\":false}"));
        mk(t).botCheck("GET", "https://x.test/p", "1.2.3.4", Map.of("user-agent", "UA"));
        assertEquals(json("{\"method\":\"GET\",\"url\":\"https://x.test/p\",\"ip\":\"1.2.3.4\","
                + "\"headers\":{\"user-agent\":\"UA\"}}"), M.readTree(t.calls.get(0).body));
    }
}
