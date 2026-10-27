package com.fpchecker.server;

import java.util.LinkedHashMap;
import java.util.Map;

/** Header filter applied by {@code botCheck}. Pass-through until the allow-list lands. */
final class BotHeaders {
    private BotHeaders() {}

    static Map<String, String> filter(Map<String, String> headers) {
        return headers == null ? new LinkedHashMap<>() : new LinkedHashMap<>(headers);
    }
}
