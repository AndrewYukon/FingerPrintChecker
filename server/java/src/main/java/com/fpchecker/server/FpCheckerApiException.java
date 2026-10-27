package com.fpchecker.server;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Raised for any non-2xx API response, and for network failures (status 0).
 *
 * <p>2xx bodies, including {@code {"ok": false, ...}} refusals, are returned as data. The message never
 * contains the secret key.
 */
public class FpCheckerApiException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final int status;
    private final String code;
    private final Integer retryAfter;
    private final JsonNode body;

    public FpCheckerApiException(int status, String code, Integer retryAfter, JsonNode body) {
        this(status, code, retryAfter, body, null);
    }

    public FpCheckerApiException(int status, String code, Integer retryAfter, JsonNode body, Throwable cause) {
        super("FpChecker API error: HTTP " + status + (code == null || code.isEmpty() ? "" : " (" + code + ")"), cause);
        this.status = status;
        this.code = code;
        this.retryAfter = retryAfter;
        this.body = body;
    }

    /** HTTP status, or 0 for a network failure. */
    public int status() {
        return status;
    }

    /** {@code body.error}, else {@code body.reason}; {@code "network_error"} / {@code "timeout"} for status 0. */
    public String code() {
        return code;
    }

    /** Retry-After in seconds, or null. */
    public Integer retryAfter() {
        return retryAfter;
    }

    /** Parsed response body, or null when it was empty or not JSON. */
    public JsonNode body() {
        return body;
    }
}
