package com.ecrew.toolkit.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.ecrew.toolkit.ai.AiIntake
import com.ecrew.toolkit.apk.ApkFileIntake
import com.ecrew.toolkit.forensics.ForensicsKit
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Forensics screen (Phase 7), root-free: contacts / SMS / call-log acquisition
 * with case export, and installed-package enumeration with on-demand APK
 * SHA-256 hashing. All output lands in Download/E-Crew/cases/<timestamp>.
 */
@Composable
fun ForensicsScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var tab by rememberSaveable { mutableStateOf(0) }

    var status by remember { mutableStateOf("idle") }
    var busy by remember { mutableStateOf(false) }
    var contacts by remember { mutableStateOf(listOf<ForensicsKit.ContactRecord>()) }
    var sms by remember { mutableStateOf(listOf<ForensicsKit.SmsRecord>()) }
    var calls by remember { mutableStateOf(listOf<ForensicsKit.CallRecord>()) }
    var apps by remember { mutableStateOf(listOf<ForensicsKit.AppRecord>()) }
    var selectedApp by remember { mutableStateOf<ForensicsKit.AppRecord?>(null) }
    var appHash by remember { mutableStateOf("") }
    var workbenchFile by remember { mutableStateOf<File?>(null) }

    var pendingAction by remember { mutableStateOf<(() -> Unit)?>(null) }
    val permLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        val action = pendingAction
        pendingAction = null
        if (grants.values.all { it }) {
            action?.invoke()
        } else {
            status = "permission denied - action cancelled"
        }
    }

    fun withPermissions(label: String, perms: List<String>, action: () -> Unit) {
        val missing = perms.filter {
            ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) {
            action()
        } else {
            status = "requesting $label permission..."
            pendingAction = action
            permLauncher.launch(missing.toTypedArray())
        }
    }

    fun run(label: String, action: suspend () -> String) {
        if (busy) return
        busy = true
        status = label
        scope.launch {
            status = try {
                action()
            } catch (e: Exception) {
                "failed: ${e.message ?: e.javaClass.simpleName}"
            }
            busy = false
        }
    }

    fun importApk(uri: Uri) {
        status = "importing APK..."
        scope.launch {
            status = try {
                val file = withContext(Dispatchers.IO) {
                    ApkFileIntake.copyToCache(context, uri)
                }
                workbenchFile = file
                "APK loaded: ${file.name}"
            } catch (e: Exception) {
                "APK import failed: ${e.message ?: e.javaClass.simpleName}"
            }
        }
    }

    val apkPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) importApk(uri)
    }

    LaunchedEffect(ApkFileIntake.pendingUri) {
        val uri = ApkFileIntake.pendingUri ?: return@LaunchedEffect
        // Clear before importing. The import runs in the composition scope, not in this
        // keyed effect, so changing the key cannot cancel the copy mid-flight.
        ApkFileIntake.pendingUri = null
        importApk(uri)
    }

    fun acquireContacts() =
        withPermissions("contacts", listOf(Manifest.permission.READ_CONTACTS)) {
            run("reading contacts...") {
                contacts = withContext(Dispatchers.IO) { ForensicsKit.readContacts(context) }
                "${contacts.size} contacts loaded"
            }
        }

    fun acquireSms() =
        withPermissions("SMS", listOf(Manifest.permission.READ_SMS)) {
            run("reading SMS...") {
                sms = withContext(Dispatchers.IO) { ForensicsKit.readSms(context) }
                "${sms.size} messages loaded"
            }
        }

    fun acquireCalls() =
        withPermissions("call log", listOf(Manifest.permission.READ_CALL_LOG)) {
            run("reading call log...") {
                calls = withContext(Dispatchers.IO) { ForensicsKit.readCalls(context) }
                "${calls.size} call records loaded"
            }
        }

    fun loadApps() {
        run("enumerating installed packages...") {
            apps = withContext(Dispatchers.IO) { ForensicsKit.readInstalledApps(context) }
            "${apps.size} packages loaded"
        }
    }

    fun doExport() {
        run("writing case folder...") {
            val result = withContext(Dispatchers.IO) {
                ForensicsKit.exportCase(context, contacts, sms, calls, apps)
            }
            if (result.isSuccess) {
                "case exported: ${result.getOrNull()}"
            } else {
                "export failed: ${result.exceptionOrNull()?.message ?: "unknown error"}"
            }
        }
    }

    fun exportCase() {
        val needsLegacyPermission = Build.VERSION.SDK_INT < 29 &&
            ContextCompat.checkSelfPermission(
                context, Manifest.permission.WRITE_EXTERNAL_STORAGE
            ) != PackageManager.PERMISSION_GRANTED
        if (needsLegacyPermission) {
            withPermissions("storage", listOf(Manifest.permission.WRITE_EXTERNAL_STORAGE)) {
                doExport()
            }
        } else {
            doExport()
        }
    }

    LaunchedEffect(selectedApp) { appHash = "" }

    val openWorkbench = workbenchFile
    if (openWorkbench != null) {
        ApkWorkbenchScreen(
            file = openWorkbench,
            onClose = { workbenchFile = null }
        )
        return
    }

    Column(Modifier.fillMaxSize()) {
        ScrollableTabRow(selectedTabIndex = tab, containerColor = Color(0xFF141A20)) {
            listOf("Acquire", "Apps", "Audit", "QF").forEachIndexed { i, name ->
                Tab(
                    selected = tab == i,
                    onClick = { tab = i },
                    text = { Text(name, fontSize = 12.sp) }
                )
            }
        }
        when (tab) {
            0 -> AcquireTab(
                contacts = contacts,
                sms = sms,
                calls = calls,
                apps = apps,
                busy = busy,
                status = status,
                onContacts = { acquireContacts() },
                onSms = { acquireSms() },
                onCalls = { acquireCalls() },
                onExport = { exportCase() },
                onAskXairex = {
                    AiIntake.ask(
                        context,
                        "Forensics acquisition summary",
                        buildString {
                            append("Root-free case acquisition summary.\n")
                            append("Contacts: ${contacts.size}\n")
                            append("SMS: ${sms.size}\n")
                            append("Call log: ${calls.size}\n")
                            append("Installed packages: ${apps.size}\n")
                            append("Status: $status\n")
                            if (contacts.isNotEmpty()) {
                                append("\nSample contacts:\n")
                                contacts.take(10).forEach {
                                    append("- ${it.name} ${it.number} (${it.type})\n")
                                }
                            }
                            if (sms.isNotEmpty()) {
                                append("\nNewest SMS entries:\n")
                                sms.take(5).forEach {
                                    append("- ${it.direction} ${it.address}: ")
                                    append(it.body.take(60))
                                    append('\n')
                                }
                            }
                            if (calls.isNotEmpty()) {
                                append("\nNewest call records:\n")
                                calls.take(5).forEach {
                                    append("- ${it.type} ${it.number} ${it.durationSeconds}s\n")
                                }
                            }
                        }
                    )
                }
            )
            1 -> AppsTab(
                apps = apps,
                busy = busy,
                status = status,
                selectedApp = selectedApp,
                appHash = appHash,
                onLoad = { loadApps() },
                onSelect = { if (!busy) selectedApp = it },
                onHash = {
                    val app = selectedApp
                    if (app != null) {
                        run("hashing ${app.packageName}...") {
                            appHash = withContext(Dispatchers.IO) {
                                ForensicsKit.sha256(File(app.apkPath))
                            }
                            "sha-256 computed"
                        }
                    }
                },
                onAnalyze = { app -> if (!busy) workbenchFile = File(app.apkPath) },
                onPickApk = {
                    apkPicker.launch(
                        arrayOf(
                            "application/vnd.android.package-archive",
                            "application/zip",
                            "application/octet-stream"
                        )
                    )
                }
            )
            2 -> SecurityAuditTab()
            else -> AcquisitionTab()
        }
    }
}

@Composable
private fun AcquireTab(
    contacts: List<ForensicsKit.ContactRecord>,
    sms: List<ForensicsKit.SmsRecord>,
    calls: List<ForensicsKit.CallRecord>,
    apps: List<ForensicsKit.AppRecord>,
    busy: Boolean,
    status: String,
    onContacts: () -> Unit,
    onSms: () -> Unit,
    onCalls: () -> Unit,
    onExport: () -> Unit,
    onAskXairex: () -> Unit
) {
    val fmt = SimpleDateFormat("MM-dd HH:mm", Locale.US)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(8.dp)) {
        Text(
            "Forensic acquisition",
            style = MaterialTheme.typography.titleMedium,
            color = AccentInfo
        )
        Spacer(Modifier.height(4.dp))
        Text(
            "Reads contacts, SMS and the call log with the matching runtime " +
                "permissions, then exports everything acquired - plus a manifest - " +
                "into one timestamped case folder in Downloads/E-Crew/cases.",
            fontSize = 11.sp,
            color = MonoGray
        )
        Spacer(Modifier.height(6.dp))
        KeyValue("Status", status, if (busy) AccentWarn else MonoGray)
        KeyValue("Contacts", contacts.size.toString())
        KeyValue("SMS", sms.size.toString())
        KeyValue("Calls", calls.size.toString())
        KeyValue("Apps", apps.size.toString())
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onContacts, enabled = !busy) { Text("Contacts") }
            OutlinedButton(onClick = onSms, enabled = !busy) { Text("SMS") }
            OutlinedButton(onClick = onCalls, enabled = !busy) { Text("Call log") }
        }
        Spacer(Modifier.height(8.dp))
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Button(onClick = onExport, enabled = !busy) { Text("Export case to Downloads") }
            TextButton(onClick = onAskXairex, enabled = !busy) {
                Text("Ask Xairex", fontSize = 11.sp)
            }
        }

        if (contacts.isNotEmpty()) {
            Spacer(Modifier.height(10.dp))
            Text("Contacts (first 20 of ${contacts.size})", fontSize = 12.sp, color = AccentInfo)
            contacts.take(20).forEach { c ->
                Text(
                    "${c.name}  ${c.number}  (${c.type})",
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MonoGray
                )
            }
        }
        if (sms.isNotEmpty()) {
            Spacer(Modifier.height(10.dp))
            Text("SMS (newest 20 of ${sms.size})", fontSize = 12.sp, color = AccentInfo)
            sms.take(20).forEach { m ->
                Text(
                    "${fmt.format(Date(m.date))}  ${m.direction}  ${m.address}",
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MonoGray
                )
                Text(
                    "  ${m.body.take(80)}",
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color(0xFFCFD8DC)
                )
            }
        }
        if (calls.isNotEmpty()) {
            Spacer(Modifier.height(10.dp))
            Text("Calls (newest 20 of ${calls.size})", fontSize = 12.sp, color = AccentInfo)
            calls.take(20).forEach { c ->
                Text(
                    "${fmt.format(Date(c.date))}  ${c.type}  ${c.number}" +
                        "  ${c.durationSeconds}s",
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MonoGray
                )
            }
        }
        Spacer(Modifier.height(12.dp))
    }
}

@Composable
private fun AppsTab(
    apps: List<ForensicsKit.AppRecord>,
    busy: Boolean,
    status: String,
    selectedApp: ForensicsKit.AppRecord?,
    appHash: String,
    onLoad: () -> Unit,
    onSelect: (ForensicsKit.AppRecord?) -> Unit,
    onHash: () -> Unit,
    onAnalyze: (ForensicsKit.AppRecord) -> Unit,
    onPickApk: () -> Unit
) {
    Column(Modifier.fillMaxSize()) {
        Column(Modifier.padding(8.dp)) {
            Text("APK analysis", style = MaterialTheme.typography.titleMedium, color = AccentInfo)
            Spacer(Modifier.height(4.dp))
            Text(
                "Full installed-package enumeration with version, APK path and size. " +
                    "Select a package to compute its APK SHA-256 or open the static APK workbench.",
                fontSize = 11.sp,
                color = MonoGray
            )
            Spacer(Modifier.height(6.dp))
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedButton(onClick = onLoad, enabled = !busy) { Text("Load packages") }
                OutlinedButton(onClick = onPickApk, enabled = !busy) { Text("Open APK file") }
            }
            Spacer(Modifier.height(4.dp))
            Text(status, fontSize = 11.sp, color = if (busy) AccentWarn else MonoGray)
            selectedApp?.let { app ->
                Spacer(Modifier.height(6.dp))
                Card(
                    Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF182027))
                ) {
                    Column(Modifier.padding(8.dp)) {
                        Text(app.label, fontSize = 13.sp)
                        Text(
                            app.packageName,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = AccentInfo
                        )
                        Text(
                            "version ${app.versionName.ifEmpty { "-" }}  " +
                                "${app.apkBytes} bytes" + if (app.system) "  [system]" else "",
                            fontSize = 11.sp,
                            color = MonoGray
                        )
                        Text(
                            app.apkPath,
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            color = MonoGray
                        )
                        if (appHash.isNotEmpty()) {
                            Text(
                                "SHA-256: $appHash",
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace,
                                color = AccentGood
                            )
                        }
                        Spacer(Modifier.height(4.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = onHash, enabled = !busy) {
                                Text("Compute SHA-256")
                            }
                            OutlinedButton(
                                onClick = { onAnalyze(app) },
                                enabled = !busy
                            ) {
                                Text("Open workbench")
                            }
                            OutlinedButton(onClick = { onSelect(null) }, enabled = !busy) {
                                Text("Close")
                            }
                        }
                    }
                }
            }
        }
        Divider(color = Color(0xFF263238))
        if (apps.isEmpty()) {
            Text(
                "No packages loaded yet - press Load packages.",
                fontSize = 11.sp,
                color = MonoGray,
                modifier = Modifier.padding(8.dp)
            )
        } else {
            LazyColumn(Modifier.fillMaxSize().padding(horizontal = 8.dp)) {
                items(apps) { app ->
                    Column(
                        Modifier.fillMaxWidth()
                            .clickable { onSelect(app) }
                            .padding(vertical = 4.dp)
                    ) {
                        Text(app.label, fontSize = 12.sp)
                        Text(
                            "${app.packageName}  ${app.apkBytes / 1024} KB",
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            color = MonoGray
                        )
                    }
                }
            }
        }
    }
}
