package com.ecrew.toolkit.apk

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.jar.JarFile

data class CertificateInfo(
    val subject: String,
    val issuer: String,
    val notBefore: Long,
    val notAfter: Long,
    val signatureAlgorithm: String,
    val sha256: String
)

data class SchemeFacts(
    val v1: Boolean,
    val v2: Boolean,
    val v3: Boolean,
    val certificates: List<CertificateInfo>,
    val warnings: List<String>
)

data class ApkSigningInfo(
    val v1: Boolean,
    val v2: Boolean,
    val v3: Boolean,
    val certificates: List<CertificateInfo>,
    val source: String,
    val warnings: List<String>
)

/**
 * Reports signature scheme presence and certificate metadata for an installed package or an
 * APK file. This reads and fingerprints certificates; it does not assert that a signature is
 * trusted or that a JAR was cryptographically verified. v2/v3 presence is read from the APK
 * Signing Block, v1 presence from META-INF signature entries.
 */
object SigningReader {
    private const val EOCD_SIGNATURE = 0x06054b50L
    private const val APK_SIG_BLOCK_MAGIC = "APK Sig Block 42"
    private const val V2_BLOCK_ID = 0x7109871aL
    private const val V3_BLOCK_ID = 0xf05368c0L
    private const val V31_BLOCK_ID = 0x1b93ad61L

    fun readSchemes(file: File): SchemeFacts {
        val warnings = ArrayList<String>()
        val v1 = readV1(file, warnings)
        val block = readSigningBlock(file, warnings)
        return SchemeFacts(
            v1 = v1.first,
            v2 = block.first,
            v3 = block.second,
            certificates = v1.second,
            warnings = warnings
        )
    }

    fun certificateInfo(certificate: X509Certificate): CertificateInfo = CertificateInfo(
        subject = certificate.subjectX500Principal.name,
        issuer = certificate.issuerX500Principal.name,
        notBefore = certificate.notBefore.time,
        notAfter = certificate.notAfter.time,
        signatureAlgorithm = certificate.sigAlgName,
        sha256 = sha256(certificate.encoded)
    )

    fun fromInstalled(context: Context, packageName: String): ApkSigningInfo {
        val manager = context.packageManager
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION")
            PackageManager.GET_SIGNATURES
        }
        val info: PackageInfo = try {
            manager.getPackageInfo(packageName, flags)
        } catch (error: PackageManager.NameNotFoundException) {
            return ApkSigningInfo(
                v1 = false,
                v2 = false,
                v3 = false,
                certificates = emptyList(),
                source = "installed package",
                warnings = listOf("package $packageName was not found")
            )
        }
        val schemeFacts = info.applicationInfo?.sourceDir?.let { sourceDir ->
            readSchemes(File(sourceDir))
        } ?: SchemeFacts(
            v1 = false,
            v2 = false,
            v3 = false,
            certificates = emptyList(),
            warnings = listOf("installed source APK path is unavailable")
        )
        val managerCertificates = certificatesFromPackageInfo(info)
        return ApkSigningInfo(
            v1 = schemeFacts.v1,
            v2 = schemeFacts.v2,
            v3 = schemeFacts.v3,
            certificates = mergeCertificates(managerCertificates, schemeFacts.certificates),
            source = "installed package",
            warnings = schemeFacts.warnings
        )
    }

    fun fromApkFile(context: Context, file: File): ApkSigningInfo {
        val manager = context.packageManager
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION")
            PackageManager.GET_SIGNATURES
        }
        val info = try {
            manager.getPackageArchiveInfo(file.absolutePath, flags)
        } catch (error: RuntimeException) {
            null
        }
        val schemeFacts = readSchemes(file)
        val managerCertificates = if (info == null) {
            emptyList()
        } else {
            certificatesFromPackageInfo(info)
        }
        return ApkSigningInfo(
            v1 = schemeFacts.v1,
            v2 = schemeFacts.v2,
            v3 = schemeFacts.v3,
            certificates = mergeCertificates(managerCertificates, schemeFacts.certificates),
            source = "APK file",
            warnings = schemeFacts.warnings +
                if (info == null) listOf("PackageManager could not read the APK") else emptyList()
        )
    }

    private fun certificatesFromPackageInfo(info: PackageInfo): List<CertificateInfo> {
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signing = info.signingInfo
            signing?.apkContentsSigners ?: emptyArray()
        } else {
            @Suppress("DEPRECATION")
            info.signatures ?: emptyArray()
        }
        return signatures.mapNotNull { signature -> certificateInfo(signature) }
    }

    private fun certificateInfo(signature: Signature): CertificateInfo? = try {
        val factory = CertificateFactory.getInstance("X.509")
        val certificate = factory.generateCertificate(signature.toByteArray().inputStream())
        if (certificate is X509Certificate) certificateInfo(certificate) else null
    } catch (_: Exception) {
        null
    }

    private fun readV1(file: File, warnings: MutableList<String>): Pair<Boolean, List<CertificateInfo>> {
        val certificates = LinkedHashMap<String, CertificateInfo>()
        var present = false
        try {
            JarFile(file).use { jar ->
                val entries = jar.entries().toList()
                for (entry in entries) {
                    if (entry.isDirectory) continue
                    val name = entry.name
                    if (!name.startsWith("META-INF/")) continue
                    val upper = name.uppercase(Locale.US)
                    if (!upper.endsWith(".RSA") && !upper.endsWith(".DSA") &&
                        !upper.endsWith(".EC")
                    ) {
                        continue
                    }
                    present = true
                    try {
                        val factory = CertificateFactory.getInstance("X.509")
                        val parsed = factory.generateCertificates(jar.getInputStream(entry))
                        for (certificate in parsed) {
                            if (certificate is X509Certificate) {
                                val info = certificateInfo(certificate)
                                certificates[info.sha256] = info
                            }
                        }
                    } catch (error: Exception) {
                        warnings.add("$name: ${error.message ?: error.javaClass.simpleName}")
                    }
                }
            }
        } catch (error: IOException) {
            warnings.add("v1 JAR read failed: ${error.message ?: "I/O error"}")
        } catch (error: SecurityException) {
            warnings.add("v1 JAR read denied: ${error.message ?: "security error"}")
        }
        return Pair(present, certificates.values.toList())
    }

    private fun readSigningBlock(
        file: File,
        warnings: MutableList<String>
    ): Pair<Boolean, Boolean> {
        if (!file.isFile) {
            warnings.add("APK file is unavailable")
            return Pair(false, false)
        }
        val length = file.length()
        if (length < 22L) return Pair(false, false)
        return try {
            RandomAccessFile(file, "r").use { raf ->
                val searchLength = minOf(length, 65_557L).toInt()
                val search = ByteArray(searchLength)
                raf.seek(length - searchLength)
                raf.readFully(search)
                var eocd = -1
                for (index in search.size - 22 downTo 0) {
                    if (leU32(search, index) == EOCD_SIGNATURE) {
                        eocd = index
                        break
                    }
                }
                if (eocd < 0) return Pair(false, false)
                val commentLength = leU16(search, eocd + 20)
                if (eocd + 22 + commentLength != search.size) {
                    // A trailing comment is acceptable, but an inconsistent comment length is
                    // not a reason to guess at a signing block.
                    return Pair(false, false)
                }
                val centralOffset = leU32(search, eocd + 16)
                if (centralOffset <= 0 || centralOffset >= length) return Pair(false, false)
                val footerOffset = centralOffset - 24
                if (footerOffset < 8) return Pair(false, false)
                val footer = ByteArray(24)
                raf.seek(footerOffset)
                raf.readFully(footer)
                val blockSize = leU64(footer, 0)
                val magic = String(footer, 8, 16, Charsets.US_ASCII)
                if (magic != APK_SIG_BLOCK_MAGIC) return Pair(false, false)
                if (blockSize < 24 || blockSize - 16 > footerOffset) {
                    warnings.add("APK Signing Block size is out of range")
                    return Pair(false, false)
                }
                val blockStart = footerOffset - (blockSize - 16)
                if (blockStart < 0) {
                    warnings.add("APK Signing Block start is out of range")
                    return Pair(false, false)
                }
                var hasV2 = false
                var hasV3 = false
                var pairOffset = blockStart + 8
                while (pairOffset + 12 <= footerOffset) {
                    raf.seek(pairOffset)
                    val pairHeader = ByteArray(12)
                    raf.readFully(pairHeader)
                    val pairSize = leU64(pairHeader, 0)
                    if (pairSize < 4 || pairSize > footerOffset - pairOffset - 8) {
                        warnings.add("APK Signing Block pair size is out of range")
                        break
                    }
                    val id = leU32(pairHeader, 8)
                    when (id) {
                        V2_BLOCK_ID -> hasV2 = true
                        V3_BLOCK_ID, V31_BLOCK_ID -> hasV3 = true
                    }
                    pairOffset += 8 + pairSize
                }
                Pair(hasV2, hasV3)
            }
        } catch (error: IOException) {
            warnings.add("APK signing block read failed: ${error.message ?: "I/O error"}")
            Pair(false, false)
        } catch (error: SecurityException) {
            warnings.add("APK signing block read denied: ${error.message ?: "security error"}")
            Pair(false, false)
        }
    }

    private fun mergeCertificates(
        first: List<CertificateInfo>,
        second: List<CertificateInfo>
    ): List<CertificateInfo> {
        val result = LinkedHashMap<String, CertificateInfo>()
        for (certificate in first + second) {
            result[certificate.sha256] = certificate
        }
        return result.values.toList()
    }

    private fun sha256(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { byte ->
            String.format(Locale.US, "%02x", byte.toInt() and 0xFF)
        }
    }

    private fun leU16(data: ByteArray, at: Int): Int =
        (data[at].toInt() and 0xFF) or ((data[at + 1].toInt() and 0xFF) shl 8)

    private fun leU32(data: ByteArray, at: Int): Long =
        (data[at].toLong() and 0xFF) or
            ((data[at + 1].toLong() and 0xFF) shl 8) or
            ((data[at + 2].toLong() and 0xFF) shl 16) or
            ((data[at + 3].toLong() and 0xFF) shl 24)

    private fun leU64(data: ByteArray, at: Int): Long {
        var value = 0L
        for (index in 0 until 8) {
            value = value or ((data[at + index].toLong() and 0xFF) shl (index * 8))
        }
        return value
    }
}
