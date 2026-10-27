package com.fpchecker.server;

/** {@link #code()} is expired | future | bad_signature | malformed_header. */
public class WebhookSignatureException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String code;

    public WebhookSignatureException(String code) {
        super("webhook signature: " + code);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
