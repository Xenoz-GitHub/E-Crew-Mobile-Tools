package com.ecrew.toolkit.ui.screens

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest

private sealed class SendAgentState {
    data object Loading : SendAgentState()
    data class Ready(val file: File, val sizeBytes: Long, val sha256: String, val qr: Bitmap) : SendAgentState()
    data class Failed(val message: String) : SendAgentState()
}

/**
 * Send Agent screen (spec Component 6): extracts the bundled agent APK from the app assets,
 * shows its SHA-256 (copyable + verifiable) as text AND as a scannable QR code, and shares
 * the APK over Bluetooth (fallback: the system chooser).
 */
@Composable
fun RemoteSendScreen() {
    val context = LocalContext.current
    var attempt by remember { mutableIntStateOf(0) }
    val state by produceState<SendAgentState>(initialValue = SendAgentState.Loading, attempt) {
        value = SendAgentState.Loading
        value = prepareAgent(context.applicationContext)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        Text("E-Crew Remote Agent", style = MaterialTheme.typography.titleLarge)
        Text(
            text = "Install this agent on the device you are supporting. It refuses to run " +
                "anything until its owner reads the consent screen, confirms legal " +
                "authorization, and enables accessibility access themselves.",
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(top = 8.dp)
        )

        when (val current = state) {
            is SendAgentState.Loading -> {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(top = 32.dp),
                    horizontalArrangement = Arrangement.Center
                ) {
                    CircularProgressIndicator()
                }
            }
            is SendAgentState.Failed -> {
                Text(
                    text = current.message,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(top = 24.dp)
                )
                Button(
                    onClick = { attempt += 1 },
                    modifier = Modifier.padding(top = 12.dp)
                ) { Text("Retry extraction") }
            }
            is SendAgentState.Ready -> {
                ReadyContent(context, current, onRetry = { attempt += 1 })
            }
        }
    }
}

@Composable
private fun ReadyContent(context: Context, state: SendAgentState.Ready, onRetry: () -> Unit) {
    var status by remember { mutableStateOf<String?>(null) }

    Card(modifier = Modifier.fillMaxWidth().padding(top = 16.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Agent package: ecrew-agent.apk", style = MaterialTheme.typography.titleSmall)
            Text(
                text = "Size: ${state.sizeBytes / 1024} KB",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 2.dp)
            )
            Text(
                text = "SHA-256",
                style = MaterialTheme.typography.labelMedium,
                modifier = Modifier.padding(top = 12.dp)
            )
            Text(
                text = state.sha256,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 4.dp)
            )
            Row(modifier = Modifier.padding(top = 12.dp)) {
                OutlinedButton(onClick = {
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    clipboard.setPrimaryClip(ClipData.newPlainText("SHA-256", state.sha256))
                    status = "SHA-256 copied"
                }) { Text("Copy") }
                OutlinedButton(
                    onClick = {
                        status = verifyHash(state.file, state.sha256)
                    },
                    modifier = Modifier.padding(start = 8.dp)
                ) { Text("Verify") }
            }
            Button(
                onClick = { status = shareOverBluetooth(context, state.file) },
                modifier = Modifier.padding(top = 12.dp)
            ) { Text("Send via Bluetooth") }
            status?.let { text ->
                Text(
                    text = text,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
        }
    }

    Text(
        text = "Verify after transfer by scanning this QR code (encodes the SHA-256):",
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.padding(top = 20.dp)
    )
    Image(
        bitmap = state.qr.asImageBitmap(),
        contentDescription = "QR code with the agent SHA-256",
        modifier = Modifier
            .padding(top = 12.dp)
            .size(232.dp)
            .background(Color.White, shape = MaterialTheme.shapes.medium)
            .padding(8.dp)
    )
    Text(
        text = "Payload: sha256:${state.sha256}",
        fontFamily = FontFamily.Monospace,
        style = MaterialTheme.typography.labelSmall,
        modifier = Modifier.padding(top = 8.dp)
    )

    Text(
        text = "The agent APK is re-extracted every time this screen opens; " +
            "Re-extract if the build changed.",
        style = MaterialTheme.typography.bodySmall,
        modifier = Modifier.padding(top = 16.dp)
    )
    OutlinedButton(onClick = onRetry, modifier = Modifier.padding(top = 8.dp)) {
        Text("Re-extract")
    }
}

private fun prepareAgent(context: Context): SendAgentState {
    return try {
        val directory = File(context.cacheDir, "remote").apply { mkdirs() }
        val file = File(directory, "ecrew-agent.apk")
        val digest = MessageDigest.getInstance("SHA-256")
        context.assets.open("ecrew-agent.apk").use { input ->
            FileOutputStream(file).use { output ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    digest.update(buffer, 0, read)
                    output.write(buffer, 0, read)
                }
            }
        }
        val hex = digest.digest().joinToString("") { "%02x".format(it) }
        SendAgentState.Ready(file, file.length(), hex, qrBitmap("sha256:$hex"))
    } catch (e: Exception) {
        SendAgentState.Failed("Cannot extract the bundled agent: ${e.message ?: e.javaClass.simpleName}")
    }
}

private fun verifyHash(file: File, expectedHex: String): String {
    return try {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        val actual = digest.digest().joinToString("") { "%02x".format(it) }
        if (actual == expectedHex) {
            "Hash verified: the cached APK matches."
        } else {
            "HASH MISMATCH - do not transfer this file."
        }
    } catch (e: Exception) {
        "Verification failed: ${e.message ?: "I/O error"}"
    }
}

private fun shareOverBluetooth(context: Context, file: File): String {
    val uri = FileProvider.getUriForFile(context, context.packageName + ".fileprovider", file)
    val share = Intent(Intent.ACTION_SEND).apply {
        type = "application/vnd.android.package-archive"
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    val bluetoothIntent = Intent(share).setPackage("com.android.bluetooth")
    return try {
        context.startActivity(bluetoothIntent)
        "Handed to the Bluetooth share app. Pick the target device there."
    } catch (_: ActivityNotFoundException) {
        try {
            context.startActivity(Intent.createChooser(share, "Send agent APK"))
            "Bluetooth share app not found; opened the system chooser instead."
        } catch (_: ActivityNotFoundException) {
            "No app can share the APK on this device."
        }
    }
}

private fun qrBitmap(payload: String): Bitmap {
    val size = 640
    val matrix = MultiFormatWriter().encode(payload, BarcodeFormat.QR_CODE, size, size)
    val pixels = IntArray(size * size)
    for (y in 0 until size) {
        val rowOffset = y * size
        for (x in 0 until size) {
            pixels[rowOffset + x] = if (matrix.get(x, y)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
        }
    }
    val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
    bitmap.setPixels(pixels, 0, size, 0, 0, size, size)
    return bitmap
}
