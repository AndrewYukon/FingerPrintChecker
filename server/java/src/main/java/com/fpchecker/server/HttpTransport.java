package com.fpchecker.server;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** JDK HttpClient transport. Redirects are never followed. */
final class HttpTransport implements Transport {
    private final HttpClient client;

    HttpTransport(Duration connectTimeout) {
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(connectTimeout)
                .build();
    }

    @Override
    public Response send(Request request) throws IOException {
        try {
            HttpRequest.BodyPublisher publisher = request.body == null
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofByteArray(request.body);
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(request.url))
                    .timeout(request.timeout)
                    .method(request.method, publisher);
            for (Map.Entry<String, String> h : request.headers.entrySet()) {
                builder.header(h.getKey(), h.getValue());
            }
            // The request timeout only covers the wait for response headers. Bound the whole call
            // (headers and body) by waiting on the future and cancelling the exchange on expiry.
            CompletableFuture<HttpResponse<byte[]>> future =
                    client.sendAsync(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
            HttpResponse<byte[]> res;
            try {
                res = future.get(request.timeout.toMillis(), TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
                future.cancel(true);
                throw new HttpTimeoutException("request timed out");
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof IOException) {
                    throw (IOException) cause;
                }
                throw new IOException("request failed: " + (cause == null ? "unknown" : cause.getClass().getSimpleName()));
            }
            Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            for (Map.Entry<String, List<String>> e : res.headers().map().entrySet()) {
                if (!e.getValue().isEmpty()) {
                    headers.put(e.getKey(), e.getValue().get(0));
                }
            }
            return new Response(res.statusCode(), headers, res.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            InterruptedIOException io = new InterruptedIOException("interrupted");
            io.initCause(e);
            throw io;
        } catch (RuntimeException e) {
            // IllegalArgumentException, SecurityException, UncheckedIOException ...: report as a network failure.
            // Only the class name is kept; the original message or cause could echo a request header value.
            throw new IOException("request failed: " + e.getClass().getSimpleName());
        }
    }
}
