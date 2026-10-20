package com.ecrew.agent

import android.content.Context
import android.content.pm.ApplicationInfo
import com.ecrew.protocol.AppInventory

/**
 * Reads the installed-package inventory for one explicit controller request.
 *
 * Read-only and request-scoped: the list is built on the session reader thread, sent once,
 * and never cached or written to disk. Package visibility filtering does not apply because
 * the agent targets API 28 (below the API 30 package-visibility change).
 */
object AppInventoryCollector {

    fun collect(context: Context): List<AppInventory.Entry> {
        val packageManager = context.packageManager
        val packages = runCatching { packageManager.getInstalledPackages(0) }
            .getOrDefault(emptyList())
        val entries = ArrayList<AppInventory.Entry>(packages.size)
        for (info in packages) {
            val application = info.applicationInfo ?: continue
            val packageName = info.packageName ?: continue
            val label = runCatching { application.loadLabel(packageManager).toString() }
                .getOrNull()
                ?.takeIf { it.isNotBlank() }
                ?: packageName
            val system = (application.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            entries.add(
                AppInventory.Entry(
                    packageName = packageName,
                    label = label,
                    version = info.versionName,
                    system = system
                )
            )
        }
        return AppInventory.sortedForDisplay(entries)
    }
}
