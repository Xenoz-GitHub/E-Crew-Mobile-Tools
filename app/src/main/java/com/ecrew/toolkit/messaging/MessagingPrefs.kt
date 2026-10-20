package com.ecrew.toolkit.messaging

import android.content.Context
import android.content.SharedPreferences
import android.os.Build

/**
 * Small settings store for messaging: the visibility toggle (default OFF per design
 * decision 1) and the user's display name (default: the device model).
 */
class MessagingPrefs(context: Context) {

    private val prefs: SharedPreferences = context.applicationContext
        .getSharedPreferences("ecrew_messaging", Context.MODE_PRIVATE)

    var visible: Boolean
        get() = prefs.getBoolean(KEY_VISIBLE, false)
        set(value) = prefs.edit().putBoolean(KEY_VISIBLE, value).apply()

    var displayName: String
        get() = prefs.getString(KEY_NAME, null)
            ?.take(MessagingProtocol.MAX_NAME_CHARS)
            ?.ifBlank { null }
            ?: defaultName()
        set(value) {
            val clean = value.trim().take(MessagingProtocol.MAX_NAME_CHARS).ifBlank { defaultName() }
            prefs.edit().putString(KEY_NAME, clean).apply()
        }

    private fun defaultName(): String = Build.MODEL ?: "E-Crew device"

    private companion object {
        const val KEY_VISIBLE = "visible"
        const val KEY_NAME = "display_name"
    }
}
