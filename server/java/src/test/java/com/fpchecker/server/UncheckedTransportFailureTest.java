package com.fpchecker.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Unchecked exceptions from the HTTP stack surface as FpCheckerApiException(0, "network_error"). */
class UncheckedTransportFailureTest {
    private static final String SK = "sk_test_SECRET_123";

    private static String everything(Throwable t) {
        StringWriter w = new StringWriter();
        t.printStackTrace(new PrintWriter(w));
        return w + String.valueOf(t.getMessage());
    }

    @Test
    void uncheckedFromTransportIsNetworkError() {
        FakeTransport t = new FakeTransport(new IllegalArgumentException("bad header value " + SK));
        FpChecker fp = new FpChecker(FpChecker.builder(SK), t, d -> { });
        FpCheckerApiException e = assertThrows(FpCheckerApiException.class, () -> fp.checkQuota(Map.of("a", 1)));
        assertEquals(0, e.status());
        assertEquals("network_error", e.code());
        assertFalse(everything(e).contains(SK));
    }

    @Test
    void uncheckedFromTransportIsRetriedOnGetLikeAnyNetworkFailure() {
        FakeTransport t = new FakeTransport(new SecurityException("x"), new SecurityException("y"),
                new SecurityException("z"));
        FpChecker fp = new FpChecker(FpChecker.builder(SK), t, d -> { });
        FpCheckerApiException e = assertThrows(FpCheckerApiException.class, fp::getStatus);
        assertEquals("network_error", e.code());
        assertEquals(3, t.calls.size());
    }

    @Test
    void httpTransportWrapsUncheckedExceptionsAsIoException() {
        HttpTransport transport = new HttpTransport(Duration.ofSeconds(1));
        Transport.Request req = new Transport.Request("GET", "http://[not a uri " + SK, Map.of("X-Secret-Key", SK), null,
                Duration.ofSeconds(1));
        IOException e = assertThrows(IOException.class, () -> transport.send(req));
        assertFalse(everything(e).contains(SK));
    }

    @Test
    void httpTransportWrapsInvalidHeaderValue() {
        HttpTransport transport = new HttpTransport(Duration.ofSeconds(1));
        Transport.Request req = new Transport.Request("GET", "http://127.0.0.1:1/", Map.of("X-Secret-Key", SK + "\n"), null,
                Duration.ofSeconds(1));
        IOException e = assertThrows(IOException.class, () -> transport.send(req));
        assertFalse(everything(e).contains(SK));
    }
}
