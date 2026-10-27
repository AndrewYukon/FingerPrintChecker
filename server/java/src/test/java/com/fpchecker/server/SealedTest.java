package com.fpchecker.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class SealedTest {
    private static final ObjectMapper M = new ObjectMapper();
    private static final JsonNode V = load();

    private static JsonNode load() {
        try {
            return M.readTree(Files.readAllBytes(Paths.get("../../test-vectors/sealed-result-v1.json")));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static List<JsonNode> cases() {
        List<JsonNode> out = new ArrayList<>();
        V.get("cases").forEach(out::add);
        return out;
    }

    private static String key(String name) {
        return V.get("keys").get(name).asText();
    }

    private static List<String> keysOf(JsonNode c) {
        List<String> out = new ArrayList<>();
        c.get("keys").forEach(k -> out.add(key(k.asText())));
        return out;
    }

    private static String code(Runnable r) {
        return assertThrows(SealedResultException.class, r::run).code();
    }

    @Test
    void vectorCountIsNotFiltered() {
        assertEquals(17, cases().size());
    }

    @ParameterizedTest
    @MethodSource("cases")
    void sealedVector(JsonNode c) {
        JsonNode expect = c.get("expect");
        if (expect.has("error")) {
            assertEquals(expect.get("error").asText(), code(() -> Sealed.unsealResult(c.get("blob").asText(), keysOf(c))));
        } else {
            assertEquals(expect, Sealed.unsealResult(c.get("blob").asText(), keysOf(c)));
        }
    }

    @Test
    void errorCodesCoveredByVectors() {
        Set<String> codes = new HashSet<>();
        for (JsonNode c : cases()) {
            if (c.get("expect").has("error")) {
                codes.add(c.get("expect").get("error").asText());
            }
        }
        assertEquals(new HashSet<>(Arrays.asList("bad_format", "unknown_key", "decrypt_failed", "invalid_key",
                "unsupported_version")), codes);
    }

    @Test
    void invalidKeyCheckedBeforeBlob() {
        assertEquals("invalid_key", code(() -> Sealed.unsealResult("!!!", List.of(key("short")))));
    }

    @Test
    void nullOrBadKeys() {
        String blob = cases().get(0).get("blob").asText();
        assertEquals("invalid_key", code(() -> Sealed.unsealResult(blob, null)));
        assertEquals("invalid_key", code(() -> Sealed.unsealResult(blob, Arrays.asList((String) null))));
        assertEquals("invalid_key", code(() -> Sealed.unsealResult(blob, List.of("not base64!"))));
        assertEquals("invalid_key", code(() -> Sealed.unsealResult(blob, List.of("abc"))));
    }

    @Test
    void nullOrEmptyBlobIsBadFormat() {
        assertEquals("bad_format", code(() -> Sealed.unsealResult(null, List.of(key("a")))));
        assertEquals("bad_format", code(() -> Sealed.unsealResult("", List.of(key("a")))));
    }

    @Test
    void unicodeDigitsAreNotBase64() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 48; i++) {
            sb.append('Ａ');
        }
        assertEquals("bad_format", code(() -> Sealed.unsealResult(sb.toString(), List.of(key("a")))));
    }

    @Test
    void errorMessageHasNoKeyMaterial() {
        SealedResultException e = assertThrows(SealedResultException.class,
                () -> Sealed.unsealResult(cases().get(0).get("blob").asText(), List.of(key("b"))));
        assertFalse(e.getMessage().contains(key("b")));
        assertTrue(e.getMessage().contains(e.code()));
    }

    static String seal(byte[] payload, String keyB64) throws Exception {
        byte[] key = Base64.getDecoder().decode(keyB64);
        byte[] id = Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(key), 4);
        byte[] head = new byte[8];
        System.arraycopy("fps1".getBytes(StandardCharsets.US_ASCII), 0, head, 0, 4);
        System.arraycopy(id, 0, head, 4, 4);
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        c.updateAAD(head);
        byte[] ct = c.doFinal(payload);
        byte[] all = new byte[8 + 12 + ct.length];
        System.arraycopy(head, 0, all, 0, 8);
        System.arraycopy(nonce, 0, all, 8, 12);
        System.arraycopy(ct, 0, all, 20, ct.length);
        return Base64.getEncoder().encodeToString(all);
    }

    static List<Object[]> edgePayloads() {
        byte[] deep = new byte[200000];
        Arrays.fill(deep, 0, 100000, (byte) '[');
        Arrays.fill(deep, 100000, 200000, (byte) ']');
        List<Object[]> out = new ArrayList<>();
        out.add(new Object[] {"nan", "{\"version\":NaN}".getBytes(StandardCharsets.UTF_8)});
        out.add(new Object[] {"inf", "{\"version\":1,\"x\":Infinity}".getBytes(StandardCharsets.UTF_8)});
        out.add(new Object[] {"neg_inf", "{\"version\":1,\"x\":-Infinity}".getBytes(StandardCharsets.UTF_8)});
        out.add(new Object[] {"deep", deep});
        out.add(new Object[] {"bad_utf8", new byte[] {(byte) 0xff, (byte) 0xfe}});
        out.add(new Object[] {"empty", new byte[0]});
        out.add(new Object[] {"bad_utf8_in_string", new byte[] {'{', '"', 'v', 'e', 'r', 's', 'i', 'o', 'n', '"', ':', '1',
            ',', '"', 'x', '"', ':', '"', (byte) 0xff, '"', '}'}});
        out.add(new Object[] {"trailing_garbage", "{\"version\":1} x".getBytes(StandardCharsets.UTF_8)});
        out.add(new Object[] {"array", "[1]".getBytes(StandardCharsets.UTF_8)});
        return out;
    }

    @ParameterizedTest
    @MethodSource("edgePayloads")
    void jsonEdgeCasesAreDecryptFailed(String name, byte[] payload) throws Exception {
        String blob = seal(payload, key("a"));
        assertEquals("decrypt_failed", code(() -> Sealed.unsealResult(blob, List.of(key("a")))), name);
    }

    @Test
    void sealHelperPositiveControl() throws Exception {
        JsonNode out = Sealed.unsealResult(seal("{\"version\":1,\"x\":2}".getBytes(StandardCharsets.UTF_8), key("a")),
                List.of(key("a")));
        assertEquals(M.readTree("{\"version\":1,\"x\":2}"), out);
    }

    @Test
    void versionMustBeNumberOne() throws Exception {
        for (String p : new String[] {"{\"version\":true}", "{\"version\":\"1\"}", "{\"version\":2}", "{}"}) {
            String blob = seal(p.getBytes(StandardCharsets.UTF_8), key("a"));
            assertEquals("unsupported_version", code(() -> Sealed.unsealResult(blob, List.of(key("a")))), p);
        }
    }
}
