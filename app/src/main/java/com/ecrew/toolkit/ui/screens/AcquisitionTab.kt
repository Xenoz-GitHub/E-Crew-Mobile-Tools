package com.ecrew.toolkit.ui.screens

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Divider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.ecrew.toolkit.acquisition.AcquisitionEngine
import com.ecrew.toolkit.acquisition.AcquisitionSession
import com.ecrew.toolkit.acquisition.EncryptedArchive
import com.ecrew.toolkit.acquisition.ModuleStatus
import com.ecrew.toolkit.acquisition.QfShell
import com.ecrew.toolkit.audit.AuditStore
import com.ecrew.toolkit.ioc.IocMatch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

private val QfCard = Color(0xFF161C22)
private val QfLine = Color(0xFF263238)
private val QfMuted = Color(0xFF8FA3A8)
private val QfGood = Color(0xFF58D68D)
private val QfWarn = Color(0xFFF4D03F)
private val QfBad = Color(0xFFFF6B6B)
private val QfInfo = Color(0xFF7FB3D5)

@Composable
fun AcquisitionTab() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var dumpGranted by remember { mutableStateOf(QfShell(context).available) }
    var includeApks by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("Ready. Public artifacts need no setup.") }
    var session by remember { mutableStateOf<AcquisitionSession?>(null) }
    var encrypted by remember { mutableStateOf<EncryptedArchive.Result?>(null) }
    var passwordVisible by remember { mutableStateOf(false) }
    var bundleName by remember { mutableStateOf("") }
    var bundleText by remember { mutableStateOf<String?>(null) }
    var muted by remember { mutableStateOf(emptySet<String>()) }
    var error by remember { mutableStateOf("") }

    val permissions = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        val denied = grants.filterValues { !it }.keys
        status = if (denied.isEmpty()) {
            "Content permissions granted."
        } else {
            "Content permissions denied: ${denied.joinToString()}"
        }
    }
    val bundlePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            try {
                val text = withContext(Dispatchers.IO) {
                    readBounded(context, uri, MAX_BUNDLE_BYTES)
                }
                bundleText = text
                bundleName = uri.lastPathSegment ?: "side-loaded STIX bundle"
                status = "Side-loaded bundle ready: ${bundleName.take(80)}"
            } catch (failure: Exception) {
                error = "Bundle read failed: ${failure.message ?: failure.javaClass.simpleName}"
            }
        }
    }

    fun start() {
        if (busy) return
        busy = true
        error = ""
        encrypted?.file?.delete()
        encrypted = null
        passwordVisible = false
        status = "Starting acquisition..."
        scope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    AcquisitionEngine(context).run(
                        includeApks = includeApks,
                        extraBundleText = bundleText,
                        progress = { message ->
                            status = message
                        }
                    )
                }
                session = result
                status = "Acquisition complete: ${result.artifacts.size} artifacts, " +
                    "${result.ioc?.matches?.size ?: 0} IoC matches."
                val store = AuditStore(context)
                try {
                    muted = store.mutedIds()
                } finally {
                    store.close()
                }
            } catch (failure: Exception) {
                error = failure.message ?: failure.javaClass.simpleName
                status = "Acquisition failed."
            } finally {
                busy = false
            }
        }
    }

    fun seal() {
        val current = session ?: return
        try {
            val password = EncryptedArchive.generatePassword()
            val target = File(context.cacheDir, "acquisition/export-${current.id}.ecqf")
            target.parentFile?.mkdirs()
            encrypted = EncryptedArchive.seal(current.archive, target, password)
            passwordVisible = true
            status = "Encrypted container created. Save the password shown below."
        } catch (failure: Exception) {
            error = failure.message ?: failure.javaClass.simpleName
        }
    }

    fun share(result: EncryptedArchive.Result) {
        try {
            val uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                result.file
            )
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "application/octet-stream"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(Intent.createChooser(intent, "Share encrypted acquisition"))
        } catch (failure: Exception) {
            error = "Share failed: ${failure.message ?: failure.javaClass.simpleName}"
        }
    }

    LazyColumn(
        Modifier.fillMaxSize().padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        item {
            Text(
                "AndroidQF acquisition and MVT-style IoC triage",
                color = QfInfo,
                fontSize = 15.sp
            )
            Text(
                "Full acquisition requires a one-time ADB setup from a computer. On Android 8, " +
                    "this cannot be done entirely on-device. Public artifacts still work without " +
                    "the setup. The app makes no external network calls.",
                fontSize = 11.sp,
                color = QfMuted,
                modifier = Modifier.padding(top = 4.dp)
            )
        }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = QfCard)) {
                Column(Modifier.padding(10.dp)) {
                    Text("One-time privileged setup", fontSize = 12.sp, color = QfInfo)
                    Text(
                        "adb shell pm grant com.ecrew.toolkit android.permission.DUMP",
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                    Text(
                        "adb shell pm grant com.ecrew.toolkit " +
                            "android.permission.PACKAGE_USAGE_STATS",
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace
                    )
                    Row(
                        Modifier.padding(top = 6.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(onClick = {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE)
                                as ClipboardManager
                            clipboard.setPrimaryClip(
                                ClipData.newPlainText(
                                    "E-Crew ADB setup",
                                    "adb shell pm grant com.ecrew.toolkit " +
                                        "android.permission.DUMP\n" +
                                        "adb shell pm grant com.ecrew.toolkit " +
                                        "android.permission.PACKAGE_USAGE_STATS"
                                )
                            )
                            status = "ADB commands copied."
                        }) { Text("Copy commands", fontSize = 10.sp) }
                        OutlinedButton(onClick = { dumpGranted = QfShell(context).available }) {
                            Text("Recheck DUMP", fontSize = 10.sp)
                        }
                    }
                    Text(
                        if (dumpGranted) {
                            "DUMP is granted; privileged dumpsys/process/log modules will run."
                        } else {
                            "DUMP is not granted; the privileged module will report PARTIAL. " +
                                "No permission is requested or granted silently."
                        },
                        fontSize = 9.sp,
                        color = if (dumpGranted) QfGood else QfWarn,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }
        }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = QfCard)) {
                Column(Modifier.padding(10.dp)) {
                    Text("Content permissions", fontSize = 12.sp, color = QfInfo)
                    Text(
                        "SMS/MMS, call log and contacts are read only with the matching runtime " +
                            "permissions. Denied permissions make those modules PARTIAL.",
                        fontSize = 9.sp,
                        color = QfMuted
                    )
                    OutlinedButton(
                        onClick = {
                            permissions.launch(
                                arrayOf(
                                    Manifest.permission.READ_SMS,
                                    Manifest.permission.READ_CALL_LOG,
                                    Manifest.permission.READ_CONTACTS,
                                    Manifest.permission.READ_EXTERNAL_STORAGE
                                )
                            )
                        },
                        modifier = Modifier.padding(top = 4.dp)
                    ) { Text("Request content permissions", fontSize = 10.sp) }
                }
            }
        }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = QfCard)) {
                Column(Modifier.padding(10.dp)) {
                    Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                        Text("Include user APK copies (cap 50 / 300 MB)", fontSize = 10.sp)
                        Spacer(Modifier.weight(1f))
                        Switch(checked = includeApks, onCheckedChange = { includeApks = it })
                    }
                    Text(
                        "APKs are only copied from non-system apps and are never installed.",
                        fontSize = 9.sp,
                        color = QfMuted
                    )
                    Row(
                        Modifier.padding(top = 6.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                bundlePicker.launch(
                                    arrayOf(
                                        "application/json",
                                        "text/plain",
                                        "application/octet-stream"
                                    )
                                )
                            },
                            enabled = !busy
                        ) { Text("Side-load STIX bundle", fontSize = 10.sp) }
                        if (bundleText != null) {
                            OutlinedButton(
                                onClick = {
                                    bundleText = null
                                    bundleName = ""
                                }
                            ) { Text("Clear bundle", fontSize = 9.sp) }
                        }
                    }
                    if (bundleName.isNotEmpty()) {
                        Text(
                            "Loaded: $bundleName",
                            fontSize = 9.sp,
                            color = QfMuted,
                            modifier = Modifier.padding(top = 2.dp)
                        )
                    }
                }
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { start() }, enabled = !busy) {
                    Text(if (busy) "Acquiring..." else "Start acquisition", fontSize = 10.sp)
                }
                if (session != null && !busy) {
                    OutlinedButton(onClick = { seal() }) {
                        Text("Encrypt", fontSize = 10.sp)
                    }
                }
            }
            Text(status, fontSize = 10.sp, color = if (busy) QfWarn else QfMuted)
            if (error.isNotEmpty()) Text(error, fontSize = 10.sp, color = QfBad)
            if (bundleText != null && !busy) {
                Text(
                    "The side-loaded bundle is matched with the bundled dataset.",
                    fontSize = 9.sp,
                    color = QfMuted
                )
            }
        }
        encrypted?.let { result ->
            item {
                Card(colors = CardDefaults.cardColors(containerColor = QfCard)) {
                    Column(Modifier.padding(10.dp)) {
                        Text("Encrypted export", fontSize = 12.sp, color = QfGood)
                        Text(
                            "AES-256-GCM; PBKDF2-HMAC-SHA256 200,000 iterations. The password " +
                                "is shown only here and is never stored or logged.",
                            fontSize = 9.sp,
                            color = QfMuted
                        )
                        val password = if (passwordVisible) result.password else "************"
                        Text(
                            "Password: $password",
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace,
                            color = QfWarn,
                            modifier = Modifier.padding(top = 4.dp)
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = { passwordVisible = !passwordVisible }) {
                                Text(
                                    if (passwordVisible) "Hide password" else "Show password",
                                    fontSize = 9.sp
                                )
                            }
                            OutlinedButton(onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE)
                                    as ClipboardManager
                                clipboard.setPrimaryClip(
                                    ClipData.newPlainText("E-Crew export password", result.password)
                                )
                                status = "Password copied; clipboard history may retain it."
                            }) { Text("Copy password", fontSize = 9.sp) }
                            Button(onClick = { share(result) }) {
                                Text("Share encrypted", fontSize = 9.sp)
                            }
                        }
                        Text(
                            result.file.absolutePath,
                            fontSize = 9.sp,
                            fontFamily = FontFamily.Monospace,
                            color = QfMuted,
                            modifier = Modifier.padding(top = 3.dp)
                        )
                        Text(
                            "SHA-256 ${result.ciphertextSha256}",
                            fontSize = 8.sp,
                            fontFamily = FontFamily.Monospace,
                            color = QfMuted
                        )
                    }
                }
            }
        }
        session?.let { result ->
            item { Divider(color = QfLine) }
            item {
                Text(
                    "Modules (${result.completedCount} complete, ${result.partialCount} partial, " +
                        "${result.failedCount} failed)",
                    fontSize = 12.sp,
                    color = QfInfo
                )
            }
            items(result.modules) { module ->
                Card(colors = CardDefaults.cardColors(containerColor = QfCard)) {
                    Column(Modifier.padding(8.dp)) {
                        Text(module.label, fontSize = 10.sp, color = QfInfo)
                        Text(
                            "${module.status.name}  ${module.artifacts.size} artifact(s)",
                            fontSize = 9.sp,
                            color = moduleColor(module.status)
                        )
                        module.error?.let { Text(it, fontSize = 8.sp, color = QfWarn) }
                    }
                }
            }
            result.ioc?.let { ioc ->
                item {
                    Text(
                        "IoC matches (${ioc.matches.size}); skipped patterns ${ioc.skippedPatterns}",
                        fontSize = 12.sp,
                        color = QfInfo
                    )
                }
                if (ioc.warnings.isNotEmpty()) {
                    item { Text(ioc.warnings.joinToString("; "), fontSize = 8.sp, color = QfWarn) }
                }
                items(ioc.matches, key = { it.indicatorId + it.evidence }) { match ->
                    IocMatchCard(
                        match = match,
                        muted = match.indicatorId in muted,
                        onMute = {
                            val store = AuditStore(context)
                            try {
                                store.setMuted(match.indicatorId, true)
                                muted = muted + match.indicatorId
                                status = "Indicator muted; future scans hide it from the ranked list."
                            } finally {
                                store.close()
                            }
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun IocMatchCard(match: IocMatch, muted: Boolean, onMute: () -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = QfCard)) {
        Column(Modifier.padding(8.dp)) {
            Text(
                "${match.severity.name}  ${match.indicatorName}",
                fontSize = 10.sp,
                color = severityColorFor(match.severity.name)
            )
            Text(match.indicatorId, fontSize = 8.sp, color = QfMuted, fontFamily = FontFamily.Monospace)
            Text(
                "${match.objectType}: ${match.value}",
                fontSize = 9.sp,
                fontFamily = FontFamily.Monospace,
                color = QfInfo
            )
            Text(
                "${match.artifact}: ${match.evidence}",
                fontSize = 9.sp,
                fontFamily = FontFamily.Monospace,
                color = QfMuted
            )
            if (!muted) {
                TextButton(onClick = onMute) { Text("Mute indicator", fontSize = 9.sp) }
            } else {
                Text("Muted", fontSize = 9.sp, color = QfMuted)
            }
        }
    }
}

private fun moduleColor(status: ModuleStatus): Color = when (status) {
    ModuleStatus.COMPLETED -> QfGood
    ModuleStatus.PARTIAL -> QfWarn
    ModuleStatus.FAILED -> QfBad
    ModuleStatus.SKIPPED -> QfMuted
}

private fun severityColorFor(name: String): Color = when (name) {
    "CRITICAL" -> QfBad
    "HIGH" -> Color(0xFFFF8A65)
    "MEDIUM" -> QfWarn
    "LOW" -> QfInfo
    else -> QfMuted
}

private fun readBounded(context: Context, uri: Uri, maxBytes: Int): String {
    val stream = context.contentResolver.openInputStream(uri)
        ?: throw IllegalArgumentException("cannot open the selected bundle")
    stream.use { input ->
        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8 * 1024)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            if (output.size() + read > maxBytes) {
                throw IllegalArgumentException("bundle exceeds the 5 MiB cap")
            }
            output.write(buffer, 0, read)
        }
        return output.toByteArray().toString(Charsets.UTF_8)
    }
}

private const val MAX_BUNDLE_BYTES = 5 * 1024 * 1024

