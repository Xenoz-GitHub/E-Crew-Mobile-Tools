package com.ecrew.toolkit.util

import android.content.Context
import java.io.File

/**
 * Offline domain blocklist. Sources (both local, no network):
 *  1. bundled asset  assets/blocklist/domains.txt
 *  2. operator-added entries in files/blocklist/custom.txt (runtime-extensible)
 *
 * Lines are plain domains (one per line); '#' starts a comment. A candidate
 * matches if it equals an entry or is a sub-domain of an entry.
 */
object Blocklist {

    @Volatile private var entries: Set<String>? = null

    fun init(context: Context) {
        if (entries != null) return
        synchronized(this) {
            if (entries != null) return
            val set = LinkedHashSet<String>()
            try {
                context.assets.open("blocklist/domains.txt").bufferedReader().useLines { lines ->
                    lines.forEach { addLine(set, it) }
                }
            } catch (e: Exception) {
                // bundled list optional at runtime
            }
            try {
                val custom = File(context.filesDir, "blocklist/custom.txt")
                if (custom.exists()) {
                    custom.bufferedReader().useLines { lines -> lines.forEach { addLine(set, it) } }
                }
            } catch (e: Exception) {
                // custom list optional
            }
            entries = set
        }
    }

    private fun addLine(set: MutableSet<String>, raw: String) {
        val line = raw.substringBefore('#').trim().lowercase().removePrefix("www.")
        if (line.isNotEmpty() && !line.contains(' ') && line.contains('.')) set.add(line)
    }

    /** Appends an operator-supplied entry to the custom list and reloads. */
    fun addCustom(context: Context, domain: String): Boolean {
        val d = domain.trim().lowercase()
        if (!d.contains('.')) return false
        return try {
            val dir = File(context.filesDir, "blocklist")
            dir.mkdirs()
            File(dir, "custom.txt").appendText("$d\n")
            entries = null
            init(context)
            true
        } catch (e: Exception) {
            false
        }
    }

    fun size(): Int = entries?.size ?: 0

    /**
     * Returns "candidate -> matched-entry" pairs for every candidate that is
     * blocked (exact match or suffix match on a parent domain).
     */
    fun check(candidates: Collection<String>): List<String> {
        val set = entries ?: return emptyList()
        val hits = LinkedHashSet<String>()
        for (raw in candidates) {
            val host = raw.trim().lowercase().removePrefix("www.").removeSuffix(".").substringBefore(':')
            if (host.isEmpty() || !host.contains('.')) continue
            if (host in set) {
                hits.add("$host (entry: $host)")
                continue
            }
            // walk parent domains: a.b.example.com -> b.example.com -> example.com
            var idx = host.indexOf('.')
            while (idx > 0) {
                val parent = host.substring(idx + 1)
                if (parent in set) {
                    hits.add("$host (entry: $parent)")
                    break
                }
                idx = host.indexOf('.', idx + 1)
            }
        }
        return hits.toList()
    }
}

