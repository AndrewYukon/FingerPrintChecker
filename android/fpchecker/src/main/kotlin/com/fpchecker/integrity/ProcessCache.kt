package com.fpchecker.integrity

import java.util.concurrent.ConcurrentHashMap

/** Remembers a successful keyed load for the life of the process; a failed load is retried next time. */
internal class ProcessCache<T> {
    private val entries = ConcurrentHashMap<String, Result<T>>()

    fun getOrLoad(key: String, loader: () -> T): T {
        entries[key]?.let { return it.getOrThrow() }
        return loader().also { entries[key] = Result.success(it) }
    }
}

/** Streams [reader] line by line (no size cap) and reports whether any line contains one of [markers]. */
internal fun readerContainsAny(reader: java.io.BufferedReader, markers: List<String>): Boolean {
    while (true) {
        val line = reader.readLine() ?: return false
        if (markers.any { line.contains(it) }) return true
    }
}
