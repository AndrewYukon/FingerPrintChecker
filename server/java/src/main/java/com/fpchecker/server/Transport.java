package com.fpchecker.server;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;

/**
 * One HTTP round trip. Package-private on purpose: an injected transport could follow redirects and forward
 * the secret key to another origin, so public constructors never accept one. Implementations must not follow
 * redirects; the client treats any 3xx as a network failure.
 */
interface Transport {
    Response send(Request request) throws IOException;

    final class Request {
        final String method;
        final String url;
        final Map<String, String> headers;
        final byte[] body;
        final Duration timeout;

        Request(String method, String url, Map<String, String> headers, byte[] body, Duration timeout) {
            this.method = method;
            this.url = url;
            this.headers = headers;
            this.body = body;
            this.timeout = timeout;
        }
    }

    final class Response {
        final int status;
        /** Looked up case-insensitively. */
        final Map<String, String> headers;
        final byte[] body;

        Response(int status, Map<String, String> headers, byte[] body) {
            this.status = status;
            this.headers = headers;
            this.body = body;
        }
    }
}
