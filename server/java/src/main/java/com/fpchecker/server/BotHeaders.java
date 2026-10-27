package com.fpchecker.server;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The forwardable header map for {@code botCheck}. {@code botCheck} applies {@link #filter} itself, so Cookie
 * and Authorization never leave your process.
 */
public final class BotHeaders {
    /** The only request headers {@code botCheck} needs. Never Cookie or Authorization. */
    public static final Set<String> BOT_CHECK_HEADERS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "sec-fetch-user",
            "signature",
            "signature-input",
            "signature-agent",
            "upgrade-insecure-requests")));

    /** Never forwarded, even when a signature covers them: they carry credentials. */
    private static final Set<String> NEVER_FORWARD = Set.of("cookie", "authorization", "proxy-authorization");

    private static final int MAX_EXTRA = 32;
    private static final Pattern PAREN_LIST = Pattern.compile("\\(([^)]*)\\)");
    private static final Pattern QUOTED = Pattern.compile("\"([^\"]*)\"");

    private BotHeaders() {}

    /** Non-{@code @} component names covered by a {@code signature-input} value (lower-cased). */
    private static List<String> coveredHeaders(String signatureInput) {
        List<String> names = new ArrayList<>();
        Matcher lists = PAREN_LIST.matcher(signatureInput);
        while (lists.find()) {
            Matcher quoted = QUOTED.matcher(lists.group(1));
            while (quoted.find()) {
                String n = quoted.group(1).toLowerCase(Locale.ROOT);
                if (!n.isEmpty() && !n.startsWith("@")) {
                    names.add(n);
                }
            }
        }
        return names;
    }

    /**
     * Keep the allowed headers plus any header named as a covered component in the request's
     * {@code signature-input} (so a signed request can be verified), with lower-cased names. Drops everything
     * else; Cookie and Authorization are never forwarded. Headers whose names differ only by case are joined
     * with ", ". A null map gives an empty map.
     */
    public static Map<String, String> filter(Map<String, String> headers) {
        Map<String, String> every = new LinkedHashMap<>();
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if (e.getValue() == null || e.getKey() == null) {
                    continue;
                }
                every.merge(e.getKey().toLowerCase(Locale.ROOT), e.getValue(), (a, b) -> a + ", " + b);
            }
        }
        Set<String> wanted = new HashSet<>(BOT_CHECK_HEADERS);
        List<String> extra = new ArrayList<>();
        for (String n : coveredHeaders(every.getOrDefault("signature-input", ""))) {
            if (!NEVER_FORWARD.contains(n)) {
                extra.add(n);
            }
        }
        wanted.addAll(extra.subList(0, Math.min(extra.size(), MAX_EXTRA)));
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : every.entrySet()) {
            if (wanted.contains(e.getKey())) {
                out.put(e.getKey(), e.getValue());
            }
        }
        return out;
    }
}
