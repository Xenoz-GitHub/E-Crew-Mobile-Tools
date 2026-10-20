package com.ecrew.toolkit.ai

import android.content.Context
import android.os.StatFs
import java.io.File
import java.io.FileOutputStream
import java.security.DigestInputStream
import java.security.MessageDigest

/** Raised when the bundled model cannot be prepared (space, integrity, IO). */
class XairexModelException(message: String) : Exception(message)

/**
 * First-run extraction of the bundled GGUF model (design note, "Model asset"): copied
 * once from assets to filesDir, SHA-256 verified while copying, then mmap-ed by the
 * engine on later launches. A marker file skips re-hashing after a verified copy.
 */
object AiModelAssets {
    const val ASSET_PATH = "models/SmolLM2-360M-Instruct-Q4_K_M.gguf"
    const val FILE_NAME = "SmolLM2-360M-Instruct-Q4_K_M.gguf"
    const val MODEL_BYTES = 270_590_880L
    const val MODEL_SHA256 =
        "2fa3f013dcdd7b99f9b237717fa0b12d75bbb89984cc1274be1471a465bac9c2"
    const val MODEL_DISPLAY_NAME = "SmolLM2-360M-Instruct Q4_K_M"
    const val MODEL_LICENSE = "Apache-2.0"
    const val MODEL_SOURCE = "bartowski/SmolLM2-360M-Instruct-GGUF (Hugging Face)"

    private const val SPACE_SLACK_BYTES = 64L * 1024 * 1024

    fun modelFile(context: Context): File = File(modelDir(context), FILE_NAME)

    fun ensureExtracted(context: Context, onProgress: (Float) -> Unit): File {
        val dir = modelDir(context).also { it.mkdirs() }
        val dest = File(dir, FILE_NAME)
        val marker = File(dir, ".verified")
        val verified = if (marker.exists()) marker.readText().trim() else ""
        if (dest.length() == MODEL_BYTES && verified == MODEL_SHA256) return dest

        val free = StatFs(dir.absolutePath).availableBytes
        if (free < MODEL_BYTES + SPACE_SLACK_BYTES) {
            throw XairexModelException(
                "Not enough free storage. Xairex needs about 260 MB of model storage " +
                    "plus working space. Free up space and try again."
            )
        }

        val temp = File(dir, "$FILE_NAME.part")
        temp.delete()
        val digest = MessageDigest.getInstance("SHA-256")
        context.assets.open(ASSET_PATH).use { raw ->
            DigestInputStream(raw, digest).use { input ->
                FileOutputStream(temp).use { output ->
                    val buffer = ByteArray(1 shl 16)
                    var copied = 0L
                    while (true) {
                        val n = input.read(buffer)
                        if (n < 0) break
                        output.write(buffer, 0, n)
                        copied += n
                        onProgress(
                            (copied.toDouble() / MODEL_BYTES.toDouble()).toFloat().coerceIn(0f, 1f)
                        )
                    }
                    output.fd.sync()
                }
            }
        }
        if (temp.length() != MODEL_BYTES) {
            temp.delete()
            throw XairexModelException("The bundled model copy is incomplete.")
        }
        val hash = digest.digest().joinToString("") { "%02x".format(it) }
        if (hash != MODEL_SHA256) {
            temp.delete()
            throw XairexModelException("The bundled model failed its integrity check.")
        }
        if (dest.exists() && !dest.delete()) {
            temp.delete()
            throw XairexModelException("The old model copy could not be replaced.")
        }
        if (!temp.renameTo(dest)) {
            temp.delete()
            throw XairexModelException("The model could not be moved into app storage.")
        }
        marker.writeText(MODEL_SHA256)
        return dest
    }

    /** Test seam: removes the extracted copy and its marker. */
    fun resetForTests(context: Context) {
        modelDir(context).deleteRecursively()
    }

    private fun modelDir(context: Context): File = File(context.filesDir, "models")
}
