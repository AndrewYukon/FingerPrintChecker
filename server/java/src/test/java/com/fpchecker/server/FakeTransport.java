package com.fpchecker.server;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Scripted transport: each queued item is a Transport.Response, an IOException or a RuntimeException. */
final class FakeTransport implements Transport {
    final LinkedList<Object> queue = new LinkedList<>();
    final List<Request> calls = new ArrayList<>();

    FakeTransport(Object... items) {
        for (Object i : items) {
            queue.add(i);
        }
    }

    @Override
    public Response send(Request request) throws IOException {
        calls.add(request);
        if (queue.isEmpty()) {
            throw new AssertionError("no more responses");
        }
        Object next = queue.removeFirst();
        if (next instanceof IOException) {
            throw (IOException) next;
        }
        if (next instanceof RuntimeException) {
            throw (RuntimeException) next;
        }
        return (Response) next;
    }

    static Response resp(int status) {
        return new Response(status, new TreeMap<>(String.CASE_INSENSITIVE_ORDER), new byte[0]);
    }

    static Response resp(int status, String body, String... headerKv) {
        Map<String, String> h = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (int i = 0; i < headerKv.length; i += 2) {
            h.put(headerKv[i], headerKv[i + 1]);
        }
        return new Response(status, h, body.getBytes(StandardCharsets.UTF_8));
    }

    static String header(Request r, String name) {
        for (Map.Entry<String, String> e : r.headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) {
                return e.getValue();
            }
        }
        return null;
    }
}
