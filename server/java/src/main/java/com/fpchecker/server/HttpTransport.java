package com.fpchecker.server;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

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
        HttpRequest.BodyPublisher publisher = request.body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(request.body);
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(request.url))
                .timeout(request.timeout)
                .method(request.method, publisher);
        for (Map.Entry<String, String> h : request.headers.entrySet()) {
            builder.header(h.getKey(), h.getValue());
        }
        try {
            HttpResponse<byte[]> res = client.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
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
        }
    }
}
