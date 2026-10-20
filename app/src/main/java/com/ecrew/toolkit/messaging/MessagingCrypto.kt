package com.ecrew.toolkit.messaging

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Arrays
import java.util.Base64
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Crypto primitives for peer messaging (design note, "Crypto design"):
 * ECDH P-256 -> HKDF-SHA-256 (hand-rolled here, RFC 5869 tested) -> AES-256-GCM via the
 * shared [com.ecrew.protocol.SecureFrameCodec]; ECDSA P-256 for identities.
 *
 * No key material is ever logged. Callers wipe derived arrays when they are done
 * ([wipe]; SecureFrameCodec wipes the session key on close).
 */
object MessagingCrypto {

    const val SESSION_KEY_BYTES = 32
    private const val CURVE = "secp256r1"
    private const val ECDH = "ECDH"
    private const val SIGNATURE_ALG = "SHA256withECDSA"

    data class EcKeyPairB64(val privateKey: PrivateKey, val publicKey: PublicKey, val publicB64: String)

    fun generateEcKeyPair(): KeyPair {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec(CURVE))
        return generator.generateKeyPair()
    }

    fun parseEcPublic(b64: String): PublicKey? = try {
        val bytes = Base64.getDecoder().decode(b64)
        if (bytes.isEmpty() || bytes.size > 512) null
        else KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(bytes))
    } catch (_: Exception) {
        null
    }

    fun parseEcPrivate(pkcs8: ByteArray): PrivateKey? = try {
        KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
    } catch (_: Exception) {
        null
    }

    fun encodePublicB64(key: PublicKey): String =
        Base64.getEncoder().encodeToString(key.encoded)

    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    /** RFC 5869 HKDF-SHA-256 (extract + expand). */
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int = SESSION_KEY_BYTES): ByteArray {
        require(length in 1..(255 * 32)) { "invalid HKDF output length" }
        val mac = Mac.getInstance("HmacSHA256")
        val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt
        mac.init(SecretKeySpec(effectiveSalt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val okm = ByteArray(length)
        var t = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            val take = minOf(t.size, length - offset)
            System.arraycopy(t, 0, okm, offset, take)
            offset += take
            counter += 1
        }
        wipe(prk)
        return okm
    }

    /** ECDH shared secret (the 32-byte X coordinate for P-256). */
    fun ecdhSharedSecret(privateKey: PrivateKey, peerPublic: PublicKey): ByteArray {
        val agreement = KeyAgreement.getInstance(ECDH)
        agreement.init(privateKey)
        agreement.doPhase(peerPublic, true)
        return agreement.generateSecret()
    }

    fun sign(privateKey: PrivateKey, data: ByteArray): ByteArray =
        Signature.getInstance(SIGNATURE_ALG).run {
            initSign(privateKey)
            update(data)
            sign()
        }

    fun verify(publicKey: PublicKey, data: ByteArray, signature: ByteArray): Boolean = try {
        Signature.getInstance(SIGNATURE_ALG).run {
            initVerify(publicKey)
            update(data)
            verify(signature)
        }
    } catch (_: Exception) {
        false
    }

    fun randomBytes(count: Int): ByteArray =
        ByteArray(count).also { SecureRandom().nextBytes(it) }

    fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    fun unb64(value: String): ByteArray? = try {
        Base64.getDecoder().decode(value)
    } catch (_: IllegalArgumentException) {
        null
    }

    /** Best-effort wipe; the array must not be used afterwards. */
    fun wipe(bytes: ByteArray) {
        Arrays.fill(bytes, 0.toByte())
    }
}
