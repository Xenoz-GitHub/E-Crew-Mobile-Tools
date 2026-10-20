package com.ecrew.toolkit.acquisition

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Compatible AES-256-GCM container around the AndroidQF ZIP. The header is authenticated as
 * GCM additional data and contains only version/KDF parameters, salt, IV and the plaintext
 * SHA-256. The password is displayed by the caller and is never written to the header,
 * preferences, audit trail or logs.
 */
object EncryptedArchive {
    private const val MAGIC = "ECQF1\n"
    private const val VERSION = 1
    private const val PBKDF2_ITERATIONS = 200_000
    private const val SALT_BYTES = 16
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128
    private const val PASSWORD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private const val PASSWORD_LENGTH = 20
    private const val MAX_HEADER_BYTES = 16 * 1024
    private const val COPY_BUFFER = 64 * 1024

    data class Result(
        val file: File,
        val password: String,
        val plaintextSha256: String,
        val ciphertextSha256: String
    )

    fun seal(input: File, output: File, password: String): Result {
        if (password.length < 16) throw AcquisitionException("password is too short")
        val salt = ByteArray(SALT_BYTES).also { SecureRandom().nextBytes(it) }
        val iv = ByteArray(IV_BYTES).also { SecureRandom().nextBytes(it) }
        val plaintextHash = sha256(input)
        val header = buildString {
            append("{\"version\":").append(VERSION)
            append(",\"cipher\":\"AES-256-GCM\"")
            append(",\"kdf\":\"PBKDF2WithHmacSHA256\"")
            append(",\"iterations\":").append(PBKDF2_ITERATIONS)
            append(",\"salt\":\"").append(base64(salt)).append('"')
            append(",\"iv\":\"").append(base64(iv)).append('"')
            append(",\"tag_bits\":").append(TAG_BITS)
            append(",\"plaintext_sha256\":\"").append(plaintextHash).append('"')
            append(",\"artifact\":\"").append(escape(input.name)).append('"')
            append('}')
        }.toByteArray(Charsets.UTF_8)
        if (header.size > MAX_HEADER_BYTES) throw AcquisitionException("header is too large")
        val key = deriveKey(password, salt)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        cipher.updateAAD(header)
        FileOutputStream(output).use { stream ->
            val data = DataOutputStream(stream)
            data.write(MAGIC.toByteArray(Charsets.US_ASCII))
            data.writeInt(header.size)
            data.write(header)
            data.flush()
            CipherOutputStream(stream, cipher).use { encrypted ->
                input.inputStream().use { plain -> plain.copyTo(encrypted, COPY_BUFFER) }
            }
        }
        return Result(output, password, plaintextHash, sha256(output))
    }

    fun open(input: File, output: File, password: String): String {
        DataInputStream(FileInputStream(input).buffered()).use { data ->
            val magic = ByteArray(MAGIC.length)
            data.readFully(magic)
            if (String(magic, Charsets.US_ASCII) != MAGIC) {
                throw AcquisitionException("not an E-Crew encrypted archive")
            }
            val headerLength = data.readInt()
            if (headerLength <= 0 || headerLength > MAX_HEADER_BYTES) {
                throw AcquisitionException("invalid archive header length")
            }
            val headerBytes = ByteArray(headerLength)
            data.readFully(headerBytes)
            val header = String(headerBytes, Charsets.UTF_8)
            val fields = parseHeader(header)
            if (fields["version"] != VERSION.toString()) {
                throw AcquisitionException("unsupported archive version")
            }
            if (fields["iterations"]?.toIntOrNull() != PBKDF2_ITERATIONS) {
                throw AcquisitionException("unexpected KDF iteration count")
            }
            if (fields["tag_bits"]?.toIntOrNull() != TAG_BITS) {
                throw AcquisitionException("unexpected GCM tag size")
            }
            val salt = decode(fields["salt"] ?: throw AcquisitionException("missing salt"))
            val iv = decode(fields["iv"] ?: throw AcquisitionException("missing IV"))
            if (salt.size != SALT_BYTES || iv.size != IV_BYTES) {
                throw AcquisitionException("invalid salt or IV length")
            }
            val key = deriveKey(password, salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
            cipher.updateAAD(headerBytes)
            val expected = fields["plaintext_sha256"]
                ?: throw AcquisitionException("missing plaintext hash")
            val actual = try {
                CipherInputStream(data, cipher).use { decrypted ->
                    FileOutputStream(output).use { plain ->
                        decrypted.copyTo(plain, COPY_BUFFER)
                    }
                }
                sha256(output)
            } catch (_: Exception) {
                output.delete()
                throw AcquisitionException("wrong password or corrupt archive")
            }
            if (expected != actual) {
                output.delete()
                throw AcquisitionException("plaintext hash mismatch")
            }
            return actual
        }
    }

    fun generatePassword(random: SecureRandom = SecureRandom()): String = buildString {
        repeat(PASSWORD_LENGTH) {
            append(PASSWORD_ALPHABET[random.nextInt(PASSWORD_ALPHABET.length)])
        }
    }

    private fun deriveKey(password: String, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, 256)
        return try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
        } finally {
            spec.clearPassword()
        }
    }

    private fun parseHeader(header: String): Map<String, String> {
        val result = LinkedHashMap<String, String>()
        val regex = Regex("\"([a-z0-9_]+)\"\\s*:\\s*(\"([^\"]*)\"|([0-9]+))")
        for (match in regex.findAll(header)) {
            result[match.groupValues[1]] = if (match.groupValues[3].isNotEmpty()) {
                match.groupValues[3]
            } else {
                match.groupValues[4]
            }
        }
        if (result.isEmpty()) throw AcquisitionException("malformed archive header")
        return result
    }

    private fun base64(bytes: ByteArray): String =
        Base64.getEncoder().withoutPadding().encodeToString(bytes)

    private fun decode(value: String): ByteArray = try {
        Base64.getDecoder().decode(value)
    } catch (_: IllegalArgumentException) {
        throw AcquisitionException("invalid base64 in header")
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(8 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return hex(digest.digest())
    }

    private fun sha256(bytes: ByteArray): String =
        hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun escape(value: String): String = value
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
}
