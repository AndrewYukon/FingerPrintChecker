package com.fpchecker.server;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Verify the {@code FPC-Signature} header on webhook deliveries. */
public final class Webhook {
    private static final Pattern WS = Pattern.compile("[ \\t\\r\\n]");
    private static final Pattern T = Pattern.compile("[0-9]{1,12}");
    private static final Pattern HEX64 = Pattern.compile("[0-9a-fA-F]{64}");
    private static final byte[] U_FFFD = {(byte) 0xEF, (byte) 0xBF, (byte) 0xBD};

    private Webhook() {}

    /** Verify with the default tolerance (300 s) and the system clock. */
    public static void verifyWebhookSignature(byte[] rawBody, String header, String secret) {
        verifyWebhookSignature(rawBody, header, secret, 300, null);
    }

    public static void verifyWebhookSignature(byte[] rawBody, String header, String secret, long toleranceSec) {
        verifyWebhookSignature(rawBody, header, secret, toleranceSec, null);
    }

    /**
     * Return normally if {@code header} is a valid, fresh signature of {@code rawBody}, else throw
     * {@link WebhookSignatureException}. {@code rawBody} must be the exact bytes received.
     *
     * @param toleranceSec allowed clock distance in seconds, in both directions; must be >= 0
     * @param now verifier clock in unix seconds, or null for the system clock
     * @throws IllegalArgumentException for a null body or secret, or a negative tolerance
     */
    public static void verifyWebhookSignature(byte[] rawBody, String header, String secret, long toleranceSec,
            Long now) {
        if (rawBody == null) {
            throw new IllegalArgumentException("rawBody must not be null");
        }
        if (secret == null) {
            throw new IllegalArgumentException("secret must not be null");
        }
        if (secret.isEmpty()) {
            throw new IllegalArgumentException("secret must not be empty");
        }
        if (toleranceSec < 0) {
            throw new IllegalArgumentException("toleranceSec must be >= 0");
        }
        double clock = now == null ? System.currentTimeMillis() / 1000.0 : now;
        Parsed p = parseHeader(header);

        byte[] expected;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update(p.tRaw.getBytes(StandardCharsets.US_ASCII));
            mac.update((byte) '.');
            expected = mac.doFinal(rawBody);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        boolean match = false;
        for (String candidate : p.v1) {
            if (HEX64.matcher(candidate).matches() && MessageDigest.isEqual(fromHex(candidate), expected)) {
                match = true; // no early exit: keep the work independent of which candidate matched
            }
        }
        if (!match) {
            throw new WebhookSignatureException("bad_signature");
        }
        if (clock - p.t > toleranceSec) {
            throw new WebhookSignatureException("expired");
        }
        if (p.t - clock > toleranceSec) {
            throw new WebhookSignatureException("future");
        }
    }

    public static void verifyWebhookSignature(String rawBody, String header, String secret) {
        verifyWebhookSignature(rawBody, header, secret, 300, null);
    }

    public static void verifyWebhookSignature(String rawBody, String header, String secret, long toleranceSec) {
        verifyWebhookSignature(rawBody, header, secret, toleranceSec, null);
    }

    /** As the byte[] form; the body is converted with UTF-8 (a lone surrogate becomes U+FFFD, as in Node). */
    public static void verifyWebhookSignature(String rawBody, String header, String secret, long toleranceSec,
            Long now) {
        if (rawBody == null) {
            throw new IllegalArgumentException("rawBody must not be null");
        }
        verifyWebhookSignature(utf8(rawBody), header, secret, toleranceSec, now);
    }

    private static byte[] utf8(String s) {
        try {
            CharsetEncoder enc = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPLACE)
                    .onUnmappableCharacter(CodingErrorAction.REPLACE)
                    .replaceWith(U_FFFD);
            ByteBuffer out = enc.encode(CharBuffer.wrap(s));
            byte[] bytes = new byte[out.remaining()];
            out.get(bytes);
            return bytes;
        } catch (java.nio.charset.CharacterCodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static final class Parsed {
        final String tRaw;
        final long t;
        final List<String> v1;

        Parsed(String tRaw, long t, List<String> v1) {
            this.tRaw = tRaw;
            this.t = t;
            this.v1 = v1;
        }
    }

    private static Parsed parseHeader(String header) {
        if (header == null || WS.matcher(header).find()) {
            throw new WebhookSignatureException("malformed_header");
        }
        String t = null;
        List<String> v1 = new ArrayList<>();
        for (String part : header.split(",", -1)) {
            int eq = part.indexOf('=');
            if (part.isEmpty() || eq < 0) {
                throw new WebhookSignatureException("malformed_header");
            }
            String key = part.substring(0, eq);
            String value = part.substring(eq + 1);
            if (key.equals("t")) {
                if (t != null) {
                    throw new WebhookSignatureException("malformed_header");
                }
                t = value;
            } else if (key.equals("v1")) {
                v1.add(value);
            }
        }
        if (t == null || !T.matcher(t).matches() || v1.isEmpty()) {
            throw new WebhookSignatureException("malformed_header");
        }
        return new Parsed(t, Long.parseLong(t), v1);
    }

    private static byte[] fromHex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }
}
