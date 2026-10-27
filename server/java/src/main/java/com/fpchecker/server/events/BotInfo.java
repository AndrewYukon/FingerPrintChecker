package com.fpchecker.server.events;

/**
 * One entry of the Bot directory and how well the request matched it. {@code category} and {@code identity} are
 * open strings: treat an unknown category as {@code other}.
 */
public final class BotInfo {
    public final String id;
    public final String name;
    public final String provider;
    public final String category;
    public final String identity;

    public BotInfo(String id, String name, String provider, String category, String identity) {
        this.id = id;
        this.name = name;
        this.provider = provider;
        this.category = category;
        this.identity = identity;
    }
}
