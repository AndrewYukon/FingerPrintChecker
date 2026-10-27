package com.fpchecker.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Decrypt the {@code sealedResult} blob returned by /v2/identify. */
public final class Sealed {
    private static final Pattern B64 = Pattern.compile("[A-Za-z0-9+/]*={0,2}");
    private static final byte[] MAGIC = {'f', 'p', 's', '1'};
    private static final int MIN_LEN = 4 + 4 + 12 + 16;
    // Jackson rejects NaN / Infinity unless ALLOW_NON_NUMERIC_NUMBERS is set (it is not), and its default
    // nesting limit turns a "[[[[..." bomb into an exception instead of a stack overflow.
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private Sealed() {}

    /** Canonical standard base64 only (regex, length, decode, re-encode equality). Null when not canonical. */
    private static byte[] strictB64(String value) {
        if (value == null || value.length() % 4 != 0 || !B64.matcher(value).matches()) {
            return null;
        }
        try {
            byte[] raw = Base64.getDecoder().decode(value);
            return Base64.getEncoder().encodeToString(raw).equals(value) ? raw : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Decrypt a sealed result. {@code keys} are base64 32-byte project keys (pass active and previous during
     * rotation).
     *
     * @throws SealedResultException with a code of bad_format, unknown_key, decrypt_failed, invalid_key or
     *     unsupported_version
     */
    public static JsonNode unsealResult(String blob, Iterable<String> keys) {
        if (keys == null) {
            throw new SealedResultException("invalid_key");
        }
        List<byte[]> keyBytes = new ArrayList<>();
        for (String k : keys) {
            byte[] b = strictB64(k);
            if (b == null || b.length != 32) {
                throw new SealedResultException("invalid_key");
            }
            keyBytes.add(b);
        }

        byte[] raw = strictB64(blob);
        if (raw == null || raw.length < MIN_LEN || !Arrays.equals(Arrays.copyOfRange(raw, 0, 4), MAGIC)) {
            throw new SealedResultException("bad_format");
        }

        byte[] aad = Arrays.copyOfRange(raw, 0, 8);
        byte[] keyId = Arrays.copyOfRange(raw, 4, 8);
        List<byte[]> candidates = new ArrayList<>();
        for (byte[] k : keyBytes) {
            if (Arrays.equals(Arrays.copyOf(sha256(k), 4), keyId)) {
                candidates.add(k);
            }
        }
        if (candidates.isEmpty()) {
            throw new SealedResultException("unknown_key");
        }

        byte[] nonce = Arrays.copyOfRange(raw, 8, 20);
        byte[] ctAndTag = Arrays.copyOfRange(raw, 20, raw.length);
        byte[] plain = null;
        for (byte[] key : candidates) {
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
                cipher.updateAAD(aad);
                plain = cipher.doFinal(ctAndTag);
                break;
            } catch (AEADBadTagException e) {
                continue;
            } catch (GeneralSecurityException e) {
                continue;
            }
        }
        if (plain == null) {
            throw new SealedResultException("decrypt_failed");
        }

        JsonNode parsed;
        try {
            // Strict UTF-8: invalid bytes must fail, never be repaired to U+FFFD.
            String text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(plain)).toString();
            parsed = MAPPER.readTree(text);
        } catch (CharacterCodingException | JsonProcessingException | RuntimeException e) {
            throw new SealedResultException("decrypt_failed");
        }
        if (parsed == null || !parsed.isObject()) {
            throw new SealedResultException("decrypt_failed");
        }
        JsonNode version = parsed.get("version");
        if (version == null || !version.isNumber() || version.decimalValue().compareTo(java.math.BigDecimal.ONE) != 0) {
            throw new SealedResultException("unsupported_version");
        }
        return parsed;
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
