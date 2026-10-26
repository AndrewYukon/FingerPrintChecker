package com.fpchecker.integrity

import java.util.concurrent.ConcurrentHashMap

/** Remembers the outcome (value or exception) of a keyed load for the life of the process. */
internal class ProcessCache<T> {
    private val entries = ConcurrentHashMap<String, Result<T>>()

    fun getOrLoad(key: String, loader: () -> T): T =
        entries.getOrPut(key) { runCatching(loader) }.getOrThrow()
}

/** Streams [reader] line by line (no size cap) and reports whether any line contains one of [markers]. */
internal fun readerContainsAny(reader: java.io.BufferedReader, markers: List<String>): Boolean {
    while (true) {
        val line = reader.readLine() ?: return false
        if (markers.any { line.contains(it) }) return true
    }
}
