package com.ecrew.toolkit.apk.fuzz

import android.content.Context

/**
 * Written-authorization attestation. It is stored once in private preferences after the
 * operator types/accepts the exact statement; nothing is granted automatically.
 */
class FuzzConsent(context: Context) {
    private val preferences = context.applicationContext
        .getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun isConfirmed(): Boolean = preferences.getBoolean(KEY_CONFIRMED, false)

    fun confirmedAt(): Long = preferences.getLong(KEY_AT, 0L)

    fun confirm(statement: String): Boolean {
        if (statement.trim() != STATEMENT) return false
        preferences.edit()
            .putBoolean(KEY_CONFIRMED, true)
            .putLong(KEY_AT, System.currentTimeMillis())
            .apply()
        return true
    }

    fun revoke() {
        preferences.edit().clear().apply()
    }

    companion object {
        const val STATEMENT =
            "I confirm that I own the target app or have written authorization to test it."
        private const val PREFERENCES = "apk_fuzz_consent"
        private const val KEY_CONFIRMED = "confirmed"
        private const val KEY_AT = "confirmed_at"
    }
}
