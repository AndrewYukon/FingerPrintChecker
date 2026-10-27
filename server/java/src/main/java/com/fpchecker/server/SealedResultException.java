package com.fpchecker.server;

/** {@link #code()} is bad_format | unknown_key | decrypt_failed | invalid_key | unsupported_version. */
public class SealedResultException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String code;

    public SealedResultException(String code) {
        super("sealed result: " + code);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
