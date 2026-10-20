package com.ecrew.toolkit.wifi

import android.net.wifi.ScanResult

/** One access point as seen in a scan. */
data class ApInfo(
    val ssid: String,
    val bssid: String,
    val rssi: Int,
    val frequency: Int,
    val channel: Int,
    val security: String,
    val capabilities: String
)

/** Forensic alert raised by the passive analysis (evil twin / downgrade…). */
data class WifiAlert(
    val kind: String,      // EVIL_TWIN | SECURITY_DOWNGRADE | AP_SECURITY_CHANGED
    val ssid: String,
    val message: String,
    val atMillis: Long
)

/**
 * Pure logic for Wi-Fi passive scanning: security parsing, channel mapping,
 * evil-twin detection (same SSID, different BSSID with different security) and
 * security-downgrade detection against scan history. No root required.
 */
object WifiKit {

    fun channelFor(freqMhz: Int): Int = when {
        freqMhz in 2412..2484 ->
            if (freqMhz == 2484) 14 else (freqMhz - 2407) / 5
        freqMhz in 5000..5900 -> (freqMhz - 5000) / 5
        freqMhz in 5955..7115 -> (freqMhz - 5950) / 5   // 6 GHz
        else -> -1
    }

    /** Parse capability string into a compact security label. */
    fun securityOf(capabilities: String): String {
        val c = capabilities.uppercase()
        return when {
            "OWE" in c -> "OPEN(OWE)"
            "SAE" in c || "WPA3" in c ->
                if ("ENT" in c) "WPA3-ENT" else "WPA3-SAE"
            "WPA2" in c -> if ("ENT" in c) "WPA2-ENT" else "WPA2-PSK"
            Regex("\\bWPA\\b").containsMatchIn(c) ->
                if ("ENT" in c) "WPA-ENT" else "WPA-PSK"
            "WEP" in c -> "WEP"
            else -> "OPEN"
        }
    }

    /** Rough strength ordering for downgrade detection. */
    fun securityRank(sec: String): Int = when {
        sec.startsWith("WPA3") -> 5
        sec.startsWith("WPA2") -> 4
        sec.startsWith("WPA") -> 3
        sec == "WEP" -> 2
        sec.startsWith("OPEN(") -> 1
        else -> 0  // OPEN
    }

    /** True when the capability string advertises Wi-Fi Protected Setup. */
    fun supportsWps(capabilities: String): Boolean =
        capabilities.contains("WPS", ignoreCase = true)

    @Suppress("DEPRECATION") // ScanResult.SSID: no legacy-compatible replacement (targetSdk 28)
    fun parse(results: List<ScanResult>): List<ApInfo> =
        results.map { r ->
            ApInfo(
                ssid = r.SSID?.trim('"') ?: "",
                bssid = r.BSSID ?: "",
                rssi = r.level,
                frequency = r.frequency,
                channel = channelFor(r.frequency),
                security = securityOf(r.capabilities ?: ""),
                capabilities = r.capabilities ?: ""
            )
        }

    /**
     * Cross-checks the current scan against in-memory history:
     *  - EVIL_TWIN: same SSID advertised by several BSSIDs with DIFFERENT
     *    security (classic twin / karma AP signature).
     *  - SECURITY_DOWNGRADE: SSID now weaker than it was in an earlier scan.
     *  - AP_SECURITY_CHANGED: one BSSID changed its own security.
     * History maps are mutated here (ssid -> last security, bssid -> last).
     */
    fun analyze(
        current: List<ApInfo>,
        ssidHistory: MutableMap<String, String>,
        bssidHistory: MutableMap<String, String>
    ): List<WifiAlert> {
        val out = mutableListOf<WifiAlert>()
        val now = System.currentTimeMillis()
        val bySsid = current.filter { it.ssid.isNotBlank() }.groupBy { it.ssid }

        for ((ssid, aps) in bySsid) {
            val secs = aps.map { it.security }.distinct()
            if (secs.size > 1) {
                val detail = aps.joinToString(", ") { "${it.bssid}=${it.security}" }
                out += WifiAlert(
                    "EVIL_TWIN", ssid,
                    "SSID '$ssid' seen with MIXED security: ${secs.joinToString("/")} - possible evil twin ($detail)",
                    now
                )
            }

            val bestNow = secs.maxByOrNull { securityRank(it) } ?: continue
            val prev = ssidHistory[ssid]
            if (prev != null && securityRank(bestNow) < securityRank(prev)) {
                out += WifiAlert(
                    "SECURITY_DOWNGRADE", ssid,
                    "SSID '$ssid' downgraded from $prev to $bestNow - possible security downgrade attack",
                    now
                )
            }
            ssidHistory[ssid] =
                if (prev == null || securityRank(bestNow) >= securityRank(prev)) bestNow else prev
        }

        for (ap in current) {
            if (ap.ssid.isBlank()) continue
            val prev = bssidHistory[ap.bssid]
            if (prev != null && prev != ap.security) {
                out += WifiAlert(
                    "AP_SECURITY_CHANGED", ap.ssid,
                    "BSSID ${ap.bssid} changed security $prev -> ${ap.security}",
                    now
                )
            }
            bssidHistory[ap.bssid] = ap.security
        }
        return out
    }
}

