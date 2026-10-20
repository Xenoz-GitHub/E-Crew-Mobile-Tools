package com.ecrew.toolkit.lan

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * OUI (Organizationally Unique Identifier) lookup for MAC address vendor resolution.
 * Uses bundled CSV asset (app/src/main/assets/lan/oui.csv) with format:
 *   prefix,vendor_name
 * Example: 00:00:0C,Cisco Systems, Inc.
 */
object OuiLookup {

    private val ouiMap = mutableMapOf<String, String>()
    private var initialized = false

    /**
     * Initialize OUI database from bundled asset.
     */
    fun init(context: Context) {
        if (initialized) return
        
        synchronized(this) {
            if (initialized) return
            
            try {
                val stream = context.assets.open("lan/oui.csv")
                BufferedReader(InputStreamReader(stream)).use { reader ->
                    reader.lineSequence()
                        .filter { it.isNotBlank() && !it.startsWith('#') }
                        .forEach { line ->
                            val parts = line.split(',', limit = 2)
                            if (parts.size == 2) {
                                val prefix = parts[0].trim().uppercase()
                                val vendor = parts[1].trim()
                                ouiMap[prefix] = vendor
                            }
                        }
                }
                initialized = true
            } catch (e: Exception) {
                // A missing or malformed asset leaves the map empty; vendors resolve to null.
            }
        }
    }

    /**
     * Get vendor name for a MAC address.
     */
    fun getVendor(mac: String): String? {
        if (!initialized) return null
        
        val cleanMac = mac.uppercase().replace(Regex("[:-]"), "")
        if (cleanMac.length < 6) return null
        
        // OUI key: first 6 hex chars in "AA:BB:CC" form (asset format above)
        val oui = "${cleanMac[0]}${cleanMac[1]}:${cleanMac[2]}${cleanMac[3]}:${cleanMac[4]}${cleanMac[5]}"
        return ouiMap[oui]
    }

    /**
     * Manually add OUI entries (for runtime extension).
     */
    fun addEntry(prefix: String, vendor: String) {
        ouiMap[prefix.uppercase()] = vendor
    }

    /**
     * Get total number of loaded OUI entries.
     */
    fun entryCount(): Int = ouiMap.size

    /**
     * Check if OUI database is initialized.
     */
    fun isInitialized(): Boolean = initialized
}