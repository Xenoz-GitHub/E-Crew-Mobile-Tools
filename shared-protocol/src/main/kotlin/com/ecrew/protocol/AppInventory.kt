package com.ecrew.protocol

import java.util.Locale

/**
 * Additive protocol v1 extension: the installed-app inventory of the agent device.
 *
 * The controller sends `app_list_req`; the agent answers with one `app_list` message. The
 * agent only serves requests inside an authenticated, user-consented session, and both sides
 * record the request/response in their audit logs. The inventory is read-only metadata and
 * is never persisted by either app.
 *
 * Bounds are enforced on both sides: at most [MAX_ENTRIES] entries and clamped string fields.
 * A hostile peer therefore cannot inflate controller memory or the UI. Entries are sorted
 * with user apps first so the cap keeps the most relevant packages.
 */
object AppInventory {

    /** Maximum entries carried by one `app_list` message. */
    const val MAX_ENTRIES = 400

    const val MAX_PACKAGE_CHARS = 160
    const val MAX_LABEL_CHARS = 120
    const val MAX_VERSION_CHARS = 64

    /** Sanity cap for the `total` counter reported by the peer. */
    const val MAX_TOTAL_REPORTED = 10_000

    /** One installed package. [version] is null when the package exposes no version name. */
    data class Entry(
        val packageName: String,
        val label: String,
        val version: String?,
        val system: Boolean
    )

    /** A validated inventory response. [total] is the number of packages before the cap. */
    data class Snapshot(
        val entries: List<Entry>,
        val total: Int,
        val truncated: Boolean
    )

    /** Serializes [snapshot] for the wire, applying the hard cap and field clamps. */
    fun toMessage(snapshot: Snapshot): Map<String, Any?> {
        val apps = ArrayList<Map<String, Any?>>(minOf(snapshot.entries.size, MAX_ENTRIES))
        for (entry in snapshot.entries) {
            if (apps.size >= MAX_ENTRIES) break
            val packageName = clean(entry.packageName, MAX_PACKAGE_CHARS) ?: continue
            val label = clean(entry.label, MAX_LABEL_CHARS) ?: packageName
            apps.add(
                mapOf(
                    "pkg" to packageName,
                    "label" to label,
                    "ver" to clean(entry.version, MAX_VERSION_CHARS),
                    "sys" to entry.system
                )
            )
        }
        val total = snapshot.total.coerceIn(apps.size, MAX_TOTAL_REPORTED)
        val truncated = snapshot.truncated ||
            apps.size < snapshot.entries.size ||
            total > apps.size
        return mapOf(
            "t" to Msg.APP_LIST,
            "apps" to apps,
            "total" to total.toLong(),
            "truncated" to truncated
        )
    }

    /**
     * Parses a peer-provided `app_list` message defensively.
     *
     * Returns null only when the message is not an inventory at all (wrong type or missing
     * `apps` array). Malformed individual entries are skipped; duplicate package names keep
     * the first occurrence; strings are clamped.
     */
    fun parse(message: Map<String, Any?>): Snapshot? {
        if (Messages.type(message) != Msg.APP_LIST) return null
        val raw = message["apps"] as? List<*> ?: return null
        val seen = HashSet<String>()
        val entries = ArrayList<Entry>(minOf(raw.size, MAX_ENTRIES))
        for (item in raw) {
            if (entries.size >= MAX_ENTRIES) break
            val map = item as? Map<*, *> ?: continue
            val packageName = clean(map["pkg"] as? String, MAX_PACKAGE_CHARS) ?: continue
            if (!seen.add(packageName)) continue
            val label = clean(map["label"] as? String, MAX_LABEL_CHARS) ?: packageName
            val version = clean(map["ver"] as? String, MAX_VERSION_CHARS)
            val system = map["sys"] as? Boolean ?: false
            entries.add(Entry(packageName, label, version, system))
        }
        val reportedTotal = Messages.long(message, "total")
            ?.coerceIn(0L, MAX_TOTAL_REPORTED.toLong())
            ?.toInt()
            ?: entries.size
        val total = maxOf(reportedTotal, entries.size)
        val truncated = (message["truncated"] as? Boolean ?: false) ||
            total > entries.size ||
            raw.size > entries.size
        return Snapshot(entries, total, truncated)
    }

    /** User apps first, then case-insensitive label, then package name. */
    fun sortedForDisplay(entries: List<Entry>): List<Entry> =
        entries.sortedWith(
            compareBy<Entry> { it.system }
                .thenBy { it.label.lowercase(Locale.ROOT) }
                .thenBy { it.packageName }
        )

    /**
     * Trims, removes control characters (labels are rendered one line per app), clamps to
     * [max] UTF-16 units without splitting a surrogate pair, and maps blank strings to null.
     */
    private fun clean(value: String?, max: Int): String? {
        if (value == null) return null
        val filtered = value.filter { it >= ' ' && it != '\u007F' }.trim()
        if (filtered.isEmpty()) return null
        return clamp(filtered, max)
    }

    private fun clamp(value: String, max: Int): String {
        if (value.length <= max) return value
        var end = max
        if (end > 0 && Character.isHighSurrogate(value[end - 1])) end -= 1
        return value.substring(0, end)
    }
}
