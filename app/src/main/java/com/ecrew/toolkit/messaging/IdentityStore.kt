package com.ecrew.toolkit.messaging

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.VisibleForTesting
import java.security.KeyPair
import java.security.KeyStore
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Loads (or creates) the per-install identity. The ECDSA private key is stored PKCS#8,
 * AES-256-GCM wrapped by a non-exportable Android Keystore key (the app key-wrapping
 * pattern used across the toolkit), in private SharedPreferences. If the wrapped blob is
 * missing or cannot be unwrapped (Keystore reset, restored backup) a fresh identity is
 * generated; peers then see a new fingerprint until they verify again - documented in the
 * implementation note.
 */
object IdentityStore {

    private const val PREFS = "ecrew_messaging"
    private const val KEY_PUBLIC = "identity_public_b64"
    private const val KEY_WRAPPED = "identity_private_wrapped"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "ecrew.messaging.identity.wrap"
    private const val IV_BYTES = 12

    @Volatile
    private var cached: MessagingIdentity? = null

    @Synchronized
    fun load(context: Context): MessagingIdentity {
        cached?.let { return it }
        val prefs = context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val identity = restore(prefs) ?: MessagingIdentity.generate().also { persist(prefs, it) }
        cached = identity
        return identity
    }

    /** Test hook: forces the next [load] to re-read the Keystore-wrapped blob. */
    @VisibleForTesting
    fun resetCacheForTests() {
        cached = null
    }

    private fun restore(prefs: SharedPreferences): MessagingIdentity? {
        val publicB64 = prefs.getString(KEY_PUBLIC, null) ?: return null
        val wrappedB64 = prefs.getString(KEY_WRAPPED, null) ?: return null
        return try {
            val publicKey = MessagingCrypto.parseEcPublic(publicB64) ?: return null
            val privateBytes = unwrap(wrappedB64) ?: return null
            val privateKey = try {
                MessagingCrypto.parseEcPrivate(privateBytes)
            } finally {
                MessagingCrypto.wipe(privateBytes)
            } ?: return null
            MessagingIdentity(KeyPair(publicKey, privateKey))
        } catch (_: Exception) {
            null
        }
    }

    private fun persist(prefs: SharedPreferences, identity: MessagingIdentity) {
        val privateBytes = identity.keyPair.private.encoded
        val wrapped = try {
            wrap(privateBytes)
        } finally {
            MessagingCrypto.wipe(privateBytes)
        }
        prefs.edit()
            .putString(KEY_PUBLIC, identity.publicKeyB64)
            .putString(KEY_WRAPPED, wrapped ?: "")
            .apply()
    }

    private fun keystoreKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    /** Returns base64(iv || ciphertext+tag) or null when the Keystore is unavailable. */
    private fun wrap(plain: ByteArray): String? = try {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // No caller IV: Keystore generates a fresh random one (randomized-encryption policy).
        cipher.init(Cipher.ENCRYPT_MODE, keystoreKey())
        val sealed = cipher.doFinal(plain)
        MessagingCrypto.b64(cipher.iv + sealed)
    } catch (_: Exception) {
        null
    }

    private fun unwrap(b64: String): ByteArray? {
        return try {
            val blob = MessagingCrypto.unb64(b64) ?: return null
            if (blob.size <= IV_BYTES) return null
            val iv = Arrays.copyOfRange(blob, 0, IV_BYTES)
            val ciphertext = Arrays.copyOfRange(blob, IV_BYTES, blob.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, keystoreKey(), GCMParameterSpec(128, iv))
            cipher.doFinal(ciphertext)
        } catch (_: Exception) {
            null
        }
    }
}
