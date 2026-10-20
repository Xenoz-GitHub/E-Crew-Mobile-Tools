// EncryptedSharedPreferences and MasterKey are deprecated as of security-crypto 1.1.0
// (Google now steers callers to app-managed keys); the feature contract mandates
// EncryptedSharedPreferences for at-rest secrets, and the API remains functional in the
// pinned stable release, so the deprecation notices are suppressed file-wide.
@file:Suppress("DEPRECATION")
package com.ecrew.agent

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom

/**
 * Encrypted at-rest storage (spec Component 7): operator name, consent flag, ADB hardening
 * toggle, and the current pairing code. Backed by a Keystore-derived AES-256-GCM master key.
 *
 * Nothing in this file logs values; the pairing code is only ever displayed on screen.
 */
object Prefs {
    private const val FILE_NAME = "ecrew_agent_secure"
    private const val KEY_CONSENT = "consent_given"
    private const val KEY_OPERATOR = "operator_name"
    private const val KEY_CODE = "pairing_code"
    private const val KEY_ADB_HARDENING = "adb_hardening"

    @Volatile
    private var cached: SharedPreferences? = null

    private fun prefs(context: Context): SharedPreferences {
        cached?.let { return it }
        synchronized(this) {
            cached?.let { return it }
            val masterKey = MasterKey.Builder(context.applicationContext)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            val created = EncryptedSharedPreferences.create(
                context.applicationContext,
                FILE_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
            cached = created
            return created
        }
    }

    fun consentGiven(context: Context): Boolean = prefs(context).getBoolean(KEY_CONSENT, false)

    fun grantConsent(context: Context, operatorName: String) {
        prefs(context).edit()
            .putBoolean(KEY_CONSENT, true)
            .putString(KEY_OPERATOR, operatorName)
            .apply()
    }

    fun operatorName(context: Context): String = prefs(context).getString(KEY_OPERATOR, "") ?: ""

    fun pairingCode(context: Context): String = prefs(context).getString(KEY_CODE, "") ?: ""

    fun regeneratePairingCode(context: Context): String {
        val code = "%06d".format(SecureRandom().nextInt(1_000_000))
        prefs(context).edit().putString(KEY_CODE, code).apply()
        return code
    }

    /** Returns the stored code, generating one when missing/legacy. */
    fun ensurePairingCode(context: Context): String {
        val existing = pairingCode(context)
        return if (existing.length == 6) existing else regeneratePairingCode(context)
    }

    fun adbHardening(context: Context): Boolean = prefs(context).getBoolean(KEY_ADB_HARDENING, false)

    fun setAdbHardening(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_ADB_HARDENING, enabled).apply()
    }
}
