package com.ecrew.toolkit.ui.screens

import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ecrew.toolkit.apk.ApkAnalysis
import com.ecrew.toolkit.apk.ApkAnalyzer
import com.ecrew.toolkit.apk.ApkAuditRecord
import com.ecrew.toolkit.apk.ApkAuditStore
import com.ecrew.toolkit.apk.ApkSigningInfo
import com.ecrew.toolkit.apk.ComponentFacts
import com.ecrew.toolkit.apk.ExportKind
import com.ecrew.toolkit.apk.Finding
import com.ecrew.toolkit.apk.FindingSource
import com.ecrew.toolkit.apk.FlutterFacts
import com.ecrew.toolkit.apk.JadxClassInfo
import com.ecrew.toolkit.apk.JadxService
import com.ecrew.toolkit.apk.JadxSession
import com.ecrew.toolkit.apk.NativeLibraryFacts
import com.ecrew.toolkit.apk.SecretMatch
import com.ecrew.toolkit.apk.Severity
import com.ecrew.toolkit.apk.SigningReader
import com.ecrew.toolkit.apk.fuzz.ActivityLauncher
import com.ecrew.toolkit.apk.fuzz.CrashWatcher
import com.ecrew.toolkit.apk.fuzz.FuzzAuditRecord
import com.ecrew.toolkit.apk.fuzz.FuzzConsent
import com.ecrew.toolkit.apk.fuzz.FuzzEngine
import com.ecrew.toolkit.apk.fuzz.FuzzResult
import com.ecrew.toolkit.apk.fuzz.FuzzSessionReport
import com.ecrew.toolkit.apk.fuzz.FuzzShizukuGateway
import com.ecrew.toolkit.apk.fuzz.FuzzStatus
import com.ecrew.toolkit.apk.fuzz.FuzzTarget
import com.ecrew.toolkit.apk.fuzz.FuzzTargets
import com.ecrew.toolkit.audit.AuditShizuku
import com.ecrew.toolkit.audit.ShizukuState
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val WorkbenchBackground = Color(0xFF10171C)
private val WorkbenchCard = Color(0xFF182027)
private val WorkbenchLine = Color(0xFF263238)
private const val MAX_SOURCE_CHARS = 400_000

/**
 * Full-static APK workbench. The caller supplies the APK file (installed package source or a
 * picked file); all parsing and scanning happens on-device in process.
 */
@Composable
fun ApkWorkbenchScreen(file: File, onClose: () -> Unit) {
    val context = LocalContext.current
    var tab by rememberSaveable { mutableStateOf(0) }
    var analysis by remember { mutableStateOf<ApkAnalysis?>(null) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf("") }
    var auditWarning by remember { mutableStateOf("") }
    var jadxSession by remember { mutableStateOf<JadxSession?>(null) }
    var jadxLoading by remember { mutableStateOf(false) }
    var jadxError by remember { mutableStateOf("") }
    var jadxRetryKey by remember { mutableStateOf(0) }
    var auditSessionId by remember { mutableStateOf("") }
    var fuzzEngine by remember { mutableStateOf<FuzzEngine?>(null) }
    var fuzzGateway by remember { mutableStateOf<FuzzShizukuGateway?>(null) }
    val tabs = listOf(
        "Overview",
        "Manifest",
        "Signing",
        "Strings",
        "Native",
        "Flutter",
        "Findings",
        "Classes",
        "Fuzzing"
    )

    DisposableEffect(Unit) {
        onDispose {
            fuzzEngine?.stop()
            fuzzGateway?.close()
            jadxSession?.close()
            jadxSession = null
        }
    }

    LaunchedEffect(file.absolutePath) {
        loading = true
        error = ""
        analysis = null
        auditWarning = ""
        val startedAt = System.currentTimeMillis()
        val sessionId = UUID.randomUUID().toString()
        auditSessionId = sessionId
        try {
            val result = withContext(Dispatchers.IO) {
                val signing: ApkSigningInfo? = try {
                    SigningReader.fromApkFile(context, file)
                } catch (failure: Exception) {
                    null
                }
                ApkAnalyzer().analyze(file, signing)
            }
            analysis = result
            val record = buildAuditRecord(sessionId, startedAt, file, result)
            auditWarning = withContext(Dispatchers.IO) { recordAudit(context, record) }
        } catch (failure: Exception) {
            val message = failure.message ?: failure.javaClass.simpleName
            error = message
            val record = ApkAuditRecord(
                sessionId = sessionId,
                startedAt = startedAt,
                finishedAt = System.currentTimeMillis(),
                fileName = file.name,
                packageName = null,
                sha256 = "",
                sizeBytes = if (file.isFile) file.length() else 0L,
                findingCount = 0,
                criticalCount = 0,
                highCount = 0,
                mediumCount = 0,
                lowCount = 0,
                infoCount = 0,
                truncated = false,
                errors = listOf(message)
            )
            auditWarning = withContext(Dispatchers.IO) { recordAudit(context, record) }
        } finally {
            loading = false
        }
    }

    LaunchedEffect(tab, jadxRetryKey) {
        if (tab != 7 || jadxSession != null || jadxLoading) return@LaunchedEffect
        jadxLoading = true
        jadxError = ""
        try {
            jadxSession = JadxService().open(file)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            jadxError = failure.message ?: failure.javaClass.simpleName
        } finally {
            jadxLoading = false
        }
    }

    BackHandler(onBack = onClose)

    Column(Modifier.fillMaxSize().background(WorkbenchBackground)) {
        Row(
            Modifier.fillMaxWidth()
                .background(Color(0xFF141A20))
                .padding(horizontal = 8.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text("APK workbench", fontSize = 16.sp, color = AccentInfo)
                Text(
                    file.name,
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MonoGray
                )
            }
            TextButton(onClick = onClose) { Text("Close") }
        }
        Divider(color = WorkbenchLine)
        if (loading) {
            Row(
                Modifier.fillMaxWidth().padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                Text("Reading APK, manifest, DEX, resources and native entries...", fontSize = 12.sp)
            }
        } else if (error.isNotEmpty()) {
            Text(
                "Analysis failed: $error",
                color = AccentBad,
                fontSize = 12.sp,
                modifier = Modifier.padding(12.dp)
            )
            if (auditWarning.isNotEmpty()) {
                Text(
                    auditWarning,
                    color = AccentWarn,
                    fontSize = 10.sp,
                    modifier = Modifier.padding(horizontal = 12.dp)
                )
            }
        } else {
            val result = analysis
            if (result != null) {
                if (auditWarning.isNotEmpty()) {
                    Text(
                        auditWarning,
                        color = AccentWarn,
                        fontSize = 10.sp,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }
                ScrollableTabRow(
                    selectedTabIndex = tab,
                    containerColor = Color(0xFF141A20),
                    edgePadding = 4.dp
                ) {
                    tabs.forEachIndexed { index, name ->
                        Tab(
                            selected = tab == index,
                            onClick = { tab = index },
                            text = { Text(name, fontSize = 11.sp) }
                        )
                    }
                }
                when (tab) {
                    0 -> OverviewTab(result)
                    1 -> ManifestTab(result)
                    2 -> SigningTab(result)
                    3 -> StringsTab(result)
                    4 -> NativeTab(result)
                    5 -> FlutterTab(result)
                    6 -> FindingsTab(result)
                    7 -> ClassesTab(
                        session = jadxSession,
                        loading = jadxLoading,
                        error = jadxError,
                        onRetry = {
                            jadxError = ""
                            jadxSession = null
                            jadxRetryKey++
                        }
                    )
                    else -> FuzzingTab(
                        result = result,
                        sessionId = auditSessionId,
                        onEngine = { engine, gateway ->
                            fuzzEngine = engine
                            fuzzGateway = gateway
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun OverviewTab(analysis: ApkAnalysis) {
    val manifest = analysis.manifest
    val findingCounts = analysis.findings.groupingBy { it.severity }.eachCount()
    LazyColumn(
        Modifier.fillMaxSize().padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        item { SectionTitle("Identity") }
        item {
            FactCard {
                FactRow("Package", manifest?.packageName ?: "unreadable")
                FactRow("Label", manifest?.application?.label ?: "not resolved")
                FactRow(
                    "Version",
                    manifest?.let { "${it.versionName ?: "-"} (${it.versionCode})" }
                        ?: "unreadable"
                )
                FactRow("APK size", formatBytes(analysis.sizeBytes))
                FactRow("APK SHA-256", analysis.sha256, monospace = true)
                FactRow(
                    "SDK",
                    manifest?.let {
                        "min ${it.minSdk ?: "-"}  target ${it.targetSdk ?: "-"}  " +
                            "compile ${it.compileSdk ?: "-"}"
                    } ?: "unreadable"
                )
            }
        }
        item { SectionTitle("Application flags") }
        item {
            FactCard {
                FactRow("Debuggable", flag(manifest?.application?.debuggable))
                FactRow("Allow backup", flag(manifest?.application?.allowBackup))
                FactRow(
                    "Cleartext traffic",
                    flag(manifest?.application?.usesCleartextTraffic)
                )
                FactRow(
                    "Network security config",
                    manifest?.application?.networkSecurityConfigId?.let { hex(it) } ?: "not set"
                )
                FactRow("Application permission", manifest?.application?.permission ?: "none")
            }
        }
        item { SectionTitle("Analysis inventory") }
        item {
            FactCard {
                FactRow("Components", manifest?.components?.size?.toString() ?: "0")
                FactRow("Declared permissions", manifest?.permissions?.size?.toString() ?: "0")
                FactRow("DEX files", analysis.dexFiles.size.toString())
                FactRow(
                    "Classes",
                    analysis.dexFiles.sumOf { it.classCount }.toString()
                )
                FactRow(
                    "DEX strings scanned",
                    analysis.secrets.scannedStrings.toString()
                )
                FactRow("Secret matches", analysis.secrets.matches.size.toString())
                FactRow("URLs", analysis.secrets.urls.size.toString())
                FactRow("Native libraries", analysis.native.libraries.size.toString())
                FactRow("Flutter", if (analysis.flutter.present) "detected" else "not detected")
                FactRow("FileProvider configs", analysis.fileProviders.configs.size.toString())
                FactRow("Findings", analysis.findings.size.toString())
            }
        }
        item { SectionTitle("Severity counts") }
        item {
            FactCard {
                Severity.entries.sortedByDescending { it.rank }.forEach { severity ->
                    FactRow(
                        severity.name,
                        (findingCounts[severity] ?: 0).toString(),
                        valueColor = severityColor(severity)
                    )
                }
            }
        }
        if (analysis.errors.isNotEmpty() || analysis.truncated) {
            item { SectionTitle("Warnings") }
            item {
                NoticeCard(
                    buildString {
                        if (analysis.truncated) {
                            append("At least one scanner reached a size/count cap; results are partial.\n")
                        }
                        analysis.errors.forEach { append("- ").append(it).append('\n') }
                    }.trimEnd()
                )
            }
        }
        item {
            Text(
                "Static checks only. Parsing does not execute the APK and does not assert that " +
                    "its signature is trusted.",
                fontSize = 10.sp,
                color = MonoGray
            )
        }
    }
}

@Composable
private fun ManifestTab(analysis: ApkAnalysis) {
    val manifest = analysis.manifest
    if (manifest == null) {
        EmptyState("Manifest facts are unavailable; see Warnings on the Overview tab.")
        return
    }
    LazyColumn(
        Modifier.fillMaxSize().padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        item { SectionTitle("Application") }
        item {
            FactCard {
                FactRow("Package", manifest.packageName)
                FactRow("Debuggable", flag(manifest.application.debuggable))
                FactRow("Allow backup", flag(manifest.application.allowBackup))
                FactRow("Cleartext", flag(manifest.application.usesCleartextTraffic))
                FactRow("Test only", flag(manifest.application.testOnly))
                FactRow("Enabled", manifest.application.enabled.toString())
                FactRow("Theme", manifest.application.themeId?.let { hex(it) } ?: "not set")
                FactRow("Icon", manifest.application.iconId?.let { hex(it) } ?: "not set")
            }
        }
        item { SectionTitle("Requested permissions") }
        if (manifest.permissions.isEmpty()) {
            item { EmptyState("No uses-permission entries.") }
        } else {
            items(manifest.permissions) { permission ->
                Text(
                    permission,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MonoGray,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 6.dp)
                )
            }
        }
        if (manifest.declaredPermissions.isNotEmpty()) {
            item { SectionTitle("Declared permissions") }
            items(manifest.declaredPermissions) { declared ->
                FactCard {
                    FactRow("Name", declared.name, monospace = true)
                    FactRow("Protection", declared.protectionLabel)
                }
            }
        }
        if (manifest.features.isNotEmpty()) {
            item { SectionTitle("Features") }
            items(manifest.features) { feature ->
                FactRow(
                    feature.name,
                    if (feature.required) "required" else "optional",
                    monospace = true
                )
            }
        }
        if (analysis.fileProviders.configs.isNotEmpty()) {
            item { SectionTitle("FileProvider path configs") }
            items(analysis.fileProviders.configs) { config ->
                FactCard {
                    FactRow("Resource", config.resourceName, monospace = true)
                    config.rules.forEach { rule ->
                        FactRow(
                            rule.type,
                            "${rule.name}: ${rule.path.ifBlank { "<root>" }}",
                            monospace = true,
                            valueColor = severityColor(rule.severity)
                        )
                    }
                }
            }
        }
        item { SectionTitle("Components (${manifest.components.size})") }
        if (manifest.components.isEmpty()) {
            item { EmptyState("No activities, services, receivers or providers.") }
        } else {
            items(
                manifest.components,
                key = { component -> component.kind.tag + ":" + component.name }
            ) { component ->
                ComponentCard(component, manifest.application.permission)
            }
        }
    }
}

@Composable
private fun ComponentCard(component: ComponentFacts, applicationPermission: String?) {
    val effectivePermission = component.permission ?: applicationPermission
    Card(colors = CardDefaults.cardColors(containerColor = WorkbenchCard)) {
        Column(Modifier.padding(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    component.kind.tag.uppercase(Locale.US),
                    fontSize = 9.sp,
                    color = AccentInfo,
                    modifier = Modifier
                        .background(Color(0xFF173D5C), RoundedCornerShape(4.dp))
                        .padding(horizontal = 4.dp, vertical = 2.dp)
                )
                Spacer(Modifier.size(6.dp))
                Text(
                    if (component.exported) "EXPORTED" else "not exported",
                    fontSize = 9.sp,
                    color = if (component.exported) AccentWarn else MonoGray
                )
                if (!component.enabled) {
                    Spacer(Modifier.size(6.dp))
                    Text("disabled", fontSize = 9.sp, color = AccentBad)
                }
            }
            Text(
                component.name,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                color = Color(0xFFDCE5E2),
                modifier = Modifier.padding(top = 2.dp)
            )
            component.label?.let { FactRow("Label", it) }
            FactRow("Export rule", exportLabel(component.exportKind))
            FactRow("Permission", effectivePermission ?: "none", monospace = true)
            if (component.authorities.isNotEmpty()) {
                FactRow("Authorities", component.authorities.joinToString("; "), monospace = true)
            }
            if (component.grantUriPermissions) {
                FactRow("Grant URI permissions", "true", valueColor = AccentWarn)
            }
            if (component.readPermission != null) {
                FactRow("Read permission", component.readPermission, monospace = true)
            }
            if (component.writePermission != null) {
                FactRow("Write permission", component.writePermission, monospace = true)
            }
            component.intentFilters.forEachIndexed { index, filter ->
                Text(
                    "intent-filter ${index + 1}",
                    fontSize = 9.sp,
                    color = MonoGray,
                    modifier = Modifier.padding(top = 4.dp)
                )
                if (filter.actions.isNotEmpty()) {
                    FactRow("actions", filter.actions.joinToString(", "), monospace = true)
                }
                if (filter.categories.isNotEmpty()) {
                    FactRow("categories", filter.categories.joinToString(", "), monospace = true)
                }
                if (filter.schemes.isNotEmpty()) {
                    FactRow("schemes", filter.schemes.joinToString(", "), monospace = true)
                }
                if (filter.hosts.isNotEmpty()) {
                    FactRow("hosts", filter.hosts.joinToString(", "), monospace = true)
                }
                if (filter.mimeTypes.isNotEmpty()) {
                    FactRow("mimeTypes", filter.mimeTypes.joinToString(", "), monospace = true)
                }
            }
        }
    }
}

@Composable
private fun SigningTab(analysis: ApkAnalysis) {
    val signing = analysis.signing
    if (signing == null) {
        EmptyState("Signing metadata could not be read.")
        return
    }
    LazyColumn(
        Modifier.fillMaxSize().padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        item { SectionTitle("Signature schemes") }
        item {
            FactCard {
                FactRow("v1 JAR", if (signing.v1) "present" else "absent")
                FactRow("v2", if (signing.v2) "present" else "absent")
                FactRow("v3", if (signing.v3) "present" else "absent")
                FactRow("Source", signing.source)
            }
        }
        item { SectionTitle("Certificates (${signing.certificates.size})") }
        if (signing.certificates.isEmpty()) {
            item { EmptyState("No certificate metadata was read.") }
        } else {
            items(signing.certificates) { certificate ->
                FactCard {
                    FactRow("Subject", certificate.subject, monospace = true)
                    FactRow("Issuer", certificate.issuer, monospace = true)
                    FactRow("Algorithm", certificate.signatureAlgorithm)
                    FactRow("Valid from", formatDate(certificate.notBefore))
                    FactRow("Valid until", formatDate(certificate.notAfter))
                    FactRow("SHA-256", certificate.sha256, monospace = true)
                }
            }
        }
        if (signing.warnings.isNotEmpty()) {
            item { SectionTitle("Warnings") }
            item { NoticeCard(signing.warnings.joinToString("\n")) }
        }
        item {
            Text(
                "Scheme presence is read from META-INF and the APK Signing Block. " +
                    "Certificate trust and cryptographic verification are not asserted here.",
                fontSize = 10.sp,
                color = MonoGray
            )
        }
    }
}

@Composable
private fun StringsTab(analysis: ApkAnalysis) {
    val secrets = analysis.secrets
    LazyColumn(
        Modifier.fillMaxSize().padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        item { SectionTitle("String scan") }
        item {
            FactCard {
                FactRow("DEX strings scanned", secrets.scannedStrings.toString())
                FactRow("Matches", secrets.matches.size.toString())
                FactRow("URLs", secrets.urls.size.toString())
                FactRow("Capped", if (secrets.truncated) "yes" else "no")
            }
        }
        item { SectionTitle("Matches (${secrets.matches.size})") }
        if (secrets.matches.isEmpty()) {
            item { EmptyState("No catalog matches in the scanned DEX strings.") }
        } else {
            items(
                secrets.matches,
                key = { match -> match.ruleId + ":" + match.sha256 + ":" + match.location }
            ) { match ->
                SecretMatchCard(match)
            }
        }
        if (secrets.urls.isNotEmpty()) {
            item { SectionTitle("URLs (${secrets.urls.size})") }
            items(secrets.urls, key = { url -> url.url }) { url ->
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 6.dp, vertical = 2.dp),
                    verticalAlignment = Alignment.Top
                ) {
                    Text(
                        url.category,
                        fontSize = 9.sp,
                        color = AccentInfo,
                        modifier = Modifier
                            .background(Color(0xFF173D5C), RoundedCornerShape(4.dp))
                            .padding(horizontal = 4.dp, vertical = 2.dp)
                    )
                    Spacer(Modifier.size(6.dp))
                    Text(
                        url.url,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = MonoGray,
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }
        item {
            Text(
                "Matches show only a first-4/last-4 preview and a SHA-256. Full values and " +
                    "URL query strings are not displayed or logged.",
                fontSize = 10.sp,
                color = MonoGray
            )
        }
    }
}

@Composable
private fun SecretMatchCard(match: SecretMatch) {
    Card(colors = CardDefaults.cardColors(containerColor = WorkbenchCard)) {
        Column(Modifier.padding(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SeverityBadge(match.severity)
                Spacer(Modifier.size(6.dp))
                Text(match.kind, fontSize = 11.sp, color = Color(0xFFDCE5E2))
            }
            FactRow("Preview", match.redacted, monospace = true)
            FactRow("SHA-256", match.sha256, monospace = true)
            FactRow("Location", match.location, monospace = true)
            match.context?.let { FactRow("Context", it, monospace = true) }
        }
    }
}

@Composable
private fun NativeTab(analysis: ApkAnalysis) {
    LazyColumn(
        Modifier.fillMaxSize().padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        item { SectionTitle("Native libraries (${analysis.native.libraries.size})") }
        if (analysis.native.libraries.isEmpty()) {
            item { EmptyState("No lib/**.so entries found.") }
        } else {
            items(analysis.native.libraries, key = { library -> library.path }) { library ->
                NativeLibraryCard(library)
            }
        }
        if (analysis.native.truncated) {
            item { NoticeCard("Native scanning reached a cap; string lists may be partial.") }
        }
    }
}

@Composable
private fun NativeLibraryCard(library: NativeLibraryFacts) {
    Card(colors = CardDefaults.cardColors(containerColor = WorkbenchCard)) {
        Column(Modifier.padding(8.dp)) {
            Text(
                library.path,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                color = AccentInfo
            )
            FactRow("Size", formatBytes(library.sizeBytes))
            FactRow("SHA-256", library.sha256, monospace = true)
            FactRow(
                "ELF",
                if (library.isElf) "yes" else "no",
                valueColor = if (library.isElf) MonoGray else AccentWarn
            )
            FactRow("64-bit", if (library.is64Bit) "yes" else "no")
            FactRow("Strings", library.strings.size.toString())
            library.error?.let { FactRow("Error", it, valueColor = AccentBad) }
            if (library.strings.isNotEmpty()) {
                Text(
                    "Sample strings",
                    fontSize = 9.sp,
                    color = MonoGray,
                    modifier = Modifier.padding(top = 4.dp)
                )
                Text(
                    library.strings.take(12).joinToString("\n") { it.take(120) },
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color(0xFFB0BEC5)
                )
                if (library.strings.size > 12) {
                    Text(
                        "${library.strings.size - 12} more strings not shown",
                        fontSize = 9.sp,
                        color = MonoGray
                    )
                }
            }
            if (library.threats.isNotEmpty()) {
                Text(
                    "Threat markers",
                    fontSize = 9.sp,
                    color = MonoGray,
                    modifier = Modifier.padding(top = 4.dp)
                )
                library.threats.forEach { threat ->
                    Row(
                        Modifier.fillMaxWidth().padding(top = 2.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        SeverityBadge(threat.severity)
                        Spacer(Modifier.size(6.dp))
                        Column(Modifier.weight(1f)) {
                            Text(threat.title, fontSize = 10.sp)
                            Text(
                                threat.preview,
                                fontSize = 9.sp,
                                fontFamily = FontFamily.Monospace,
                                color = MonoGray
                            )
                        }
                    }
                }
            }
            if (library.truncated) {
                Text("Library string extraction was capped.", fontSize = 9.sp, color = AccentWarn)
            }
        }
    }
}

@Composable
private fun FlutterTab(analysis: ApkAnalysis) {
    val flutter = analysis.flutter
    LazyColumn(
        Modifier.fillMaxSize().padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        item { SectionTitle("Flutter") }
        item {
            FactCard {
                FactRow("Present", if (flutter.present) "yes" else "no")
                FactRow("Engine", flutter.enginePath ?: "not found", monospace = true)
                FactRow("Dart app", flutter.appPath ?: "not found", monospace = true)
                FactRow("Dart strings", flutter.dartStrings.size.toString())
                FactRow("Capped", if (flutter.truncated) "yes" else "no")
                flutter.error?.let { FactRow("Error", it, valueColor = AccentBad) }
            }
        }
        if (!flutter.present) {
            item { EmptyState("No libflutter.so or libapp.so entries found.") }
        } else {
            item { SectionTitle("Bridges (${flutter.bridges.size})") }
            if (flutter.bridges.isEmpty()) {
                item { EmptyState("No known Dart bridge markers found.") }
            } else {
                items(flutter.bridges, key = { bridge -> bridge.id }) { bridge ->
                    FactCard {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            SeverityBadge(bridge.severity)
                            Spacer(Modifier.size(6.dp))
                            Text(bridge.title, fontSize = 11.sp)
                        }
                        Text(
                            bridge.evidence,
                            fontSize = 9.sp,
                            fontFamily = FontFamily.Monospace,
                            color = MonoGray,
                            modifier = Modifier.padding(top = 3.dp)
                        )
                    }
                }
            }
            if (flutter.dartStrings.isNotEmpty()) {
                item { SectionTitle("Dart strings") }
                item {
                    Text(
                        flutter.dartStrings.take(30).joinToString("\n") { it.take(120) },
                        fontSize = 9.sp,
                        fontFamily = FontFamily.Monospace,
                        color = MonoGray
                    )
                }
                if (flutter.dartStrings.size > 30) {
                    item {
                        Text(
                            "${flutter.dartStrings.size - 30} more strings not shown",
                            fontSize = 9.sp,
                            color = MonoGray
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun FuzzingTab(
    result: ApkAnalysis,
    sessionId: String,
    onEngine: (FuzzEngine?, FuzzShizukuGateway?) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val consentStore = remember(context) { FuzzConsent(context) }
    var consentConfirmed by remember { mutableStateOf(consentStore.isConfirmed()) }
    var statement by rememberSaveable { mutableStateOf("") }
    var shizukuState by remember { mutableStateOf(AuditShizuku.state(context)) }
    var running by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    var report by remember { mutableStateOf<FuzzSessionReport?>(null) }
    var launchNote by remember { mutableStateOf("") }
    var engine by remember { mutableStateOf<FuzzEngine?>(null) }
    val targets = remember(result.manifest) {
        result.manifest?.let { FuzzTargets.exported(it) } ?: emptyList()
    }
    val launcher = remember(context) { ActivityLauncher(context) }

    DisposableEffect(Unit) {
        val listener = AuditShizuku.addPermissionResultListener { granted ->
            shizukuState = if (granted) ShizukuState.READY else ShizukuState.PERMISSION_REQUIRED
        }
        onDispose { AuditShizuku.removePermissionResultListener(listener) }
    }

    if (!consentConfirmed) {
        Column(
            Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                "Dynamic component fuzzing attestation",
                fontSize = 16.sp,
                color = AccentInfo
            )
            Text(
                "Fuzzing sends malformed intents, provider queries and broadcasts to another " +
                    "app. It can change that app's data, crash it, or expose its files. Only test " +
                    "an app you own or are authorized in writing to test.",
                fontSize = 12.sp,
                color = MonoGray
            )
            Text(FuzzConsent.STATEMENT, fontSize = 12.sp, color = AccentWarn)
            OutlinedTextField(
                value = statement,
                onValueChange = { statement = it },
                label = { Text("Type the statement exactly", fontSize = 10.sp) },
                modifier = Modifier.fillMaxWidth()
            )
            Button(
                onClick = {
                    if (consentStore.confirm(statement)) {
                        consentConfirmed = true
                        statement = ""
                        error = ""
                    } else {
                        error = "The attestation text does not match."
                    }
                },
                enabled = statement.trim() == FuzzConsent.STATEMENT
            ) { Text("Record authorization", fontSize = 10.sp) }
            if (error.isNotEmpty()) {
                Text(error, fontSize = 10.sp, color = AccentBad)
            }
            Text(
                "No fuzzing starts until this attestation is recorded, Shizuku is ready, and " +
                    "the operator presses Start fuzzing.",
                fontSize = 9.sp,
                color = MonoGray
            )
        }
        return
    }

    LazyColumn(
        Modifier.fillMaxSize().padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        item {
            NoticeCard(
                "Dynamic fuzzing requires Shizuku. On Android 8, start Shizuku once via ADB " +
                    "from a computer. Only test apps you own or are authorized in writing to test."
            )
        }
        item { SectionTitle("Written-authorization attestation") }
        item {
            FactCard {
                FactRow("Status", "recorded", valueColor = AccentGood)
                FactRow("Recorded at", formatDate(consentStore.confirmedAt()))
                TextButton(onClick = {
                    consentStore.revoke()
                    consentConfirmed = false
                    statement = ""
                }) { Text("Revoke authorization record") }
            }
        }
        item { SectionTitle("Shizuku crash capture") }
        item {
            FactCard {
                FactRow("State", shizukuState.name)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = {
                        shizukuState = AuditShizuku.state(context)
                    }) { Text("Check", fontSize = 10.sp) }
                    OutlinedButton(
                        onClick = {
                            if (shizukuState == ShizukuState.PERMISSION_REQUIRED) {
                                AuditShizuku.requestPermission()
                            }
                        },
                        enabled = shizukuState == ShizukuState.PERMISSION_REQUIRED
                    ) { Text("Request access", fontSize = 10.sp) }
                }
                if (shizukuState != ShizukuState.READY) {
                    Text(
                        "Crash capture is unavailable until Shizuku is running and E-Crew has " +
                            "permission. Fuzzing is disabled in that state.",
                        fontSize = 9.sp,
                        color = AccentWarn,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }
        }
        item { SectionTitle("Exported targets (${targets.size})") }
        if (targets.isEmpty()) {
            item { EmptyState("No exported, enabled components were found.") }
        } else {
            items(targets, key = { target -> target.kind.tag + ":" + target.name }) { target ->
                Card(colors = CardDefaults.cardColors(containerColor = WorkbenchCard)) {
                    Column(Modifier.padding(8.dp)) {
                        Text(
                            target.name,
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            color = AccentInfo
                        )
                        FactRow("Kind", target.kind.tag)
                        FactRow("Permission", target.permission ?: "none")
                        if (target.kind.tag == "activity") {
                            ActivityLaunchCard(target, launcher) { note -> launchNote = note }
                        }
                    }
                }
            }
        }
        if (launchNote.isNotEmpty()) {
            item { Text(launchNote, fontSize = 9.sp, color = MonoGray) }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        error = ""
                        report = null
                        running = true
                        val gateway = FuzzShizukuGateway(context)
                        val newEngine = FuzzEngine(context, CrashWatcher(gateway))
                        engine = newEngine
                        onEngine(newEngine, gateway)
                        val activeSessionId = sessionId.ifEmpty {
                            UUID.randomUUID().toString()
                        }
                        scope.launch(Dispatchers.IO) {
                            val store = ApkAuditStore(context)
                            try {
                                store.recordFuzz(
                                    FuzzAuditRecord(
                                        sessionId = activeSessionId,
                                        eventAt = consentStore.confirmedAt(),
                                        targetPackage = targets.first().packageName,
                                        component = "<attestation>",
                                        componentType = "session",
                                        payloadId = "attestation",
                                        status = "AUTHORIZED",
                                        latencyMs = 0L,
                                        crashSummary = null
                                    )
                                )
                                val summary = newEngine.run(targets, true) { fuzzResult ->
                                    store.recordFuzz(
                                        FuzzAuditRecord(
                                            sessionId = activeSessionId,
                                            eventAt = System.currentTimeMillis(),
                                            targetPackage = fuzzResult.target.packageName,
                                            component = fuzzResult.target.name,
                                            componentType = fuzzResult.target.kind.tag,
                                            payloadId = fuzzResult.payloadId,
                                            status = fuzzResult.status.name,
                                            latencyMs = fuzzResult.latencyMs,
                                            crashSummary = fuzzResult.crash?.summary()
                                        )
                                    )
                                }
                                store.recordFuzz(
                                    FuzzAuditRecord(
                                        sessionId = activeSessionId,
                                        eventAt = System.currentTimeMillis(),
                                        targetPackage = targets.first().packageName,
                                        component = "<session>",
                                        componentType = "session",
                                        payloadId = "session_end",
                                        status = "FINISHED",
                                        latencyMs = summary.finishedAt - summary.startedAt,
                                        crashSummary = "crashes=${summary.crashCount}; " +
                                            "results=${summary.results.size}"
                                    )
                                )
                                withContext(Dispatchers.Main) { report = summary }
                            } catch (cancelled: CancellationException) {
                                throw cancelled
                            } catch (failure: Exception) {
                                withContext(Dispatchers.Main) {
                                    error = failure.message ?: failure.javaClass.simpleName
                                }
                            } finally {
                                store.close()
                                gateway.close()
                                withContext(NonCancellable + Dispatchers.Main) {
                                    running = false
                                    engine = null
                                }
                            }
                        }
                    },
                    enabled = consentConfirmed &&
                        shizukuState == ShizukuState.READY &&
                        targets.isNotEmpty() &&
                        !running
                ) { Text(if (running) "Fuzzing..." else "Start fuzzing", fontSize = 10.sp) }
                OutlinedButton(
                    onClick = { engine?.stop() },
                    enabled = running
                ) { Text("Stop", fontSize = 10.sp) }
            }
        }
        if (error.isNotEmpty()) item { NoticeCard(error) }
        report?.let { summary ->
            item { SectionTitle("Session result") }
            item {
                FactCard {
                    FactRow("Targets", summary.targets.size.toString())
                    FactRow("Results", summary.results.size.toString())
                    FactRow("Crashes", summary.crashCount.toString())
                    FactRow("Sent", summary.sentCount.toString())
                    FactRow("Blocked", summary.blockedCount.toString())
                    FactRow("Timeouts", summary.timeoutCount.toString())
                    FactRow("Errors", summary.errorCount.toString())
                    FactRow(
                        "Crash capture",
                        if (summary.crashCaptureDegraded) "degraded" else "Shizuku",
                        valueColor = if (summary.crashCaptureDegraded) AccentWarn else AccentGood
                    )
                }
            }
            if (summary.errors.isNotEmpty()) {
                item { NoticeCard(summary.errors.joinToString("\n")) }
            }
            items(
                summary.results,
                key = { fuzzResult ->
                    fuzzResult.target.name + ":" + fuzzResult.payloadId + ":" +
                        fuzzResult.status.name
                }
            ) { fuzzResult -> FuzzResultCard(fuzzResult) }
        }
    }
}

@Composable
private fun ActivityLaunchCard(
    target: FuzzTarget,
    launcher: ActivityLauncher,
    onNote: (String) -> Unit
) {
    var extraKey by remember(target.name) { mutableStateOf("") }
    var extraValue by remember(target.name) { mutableStateOf("") }
    var deepLink by remember(target.name) { mutableStateOf("") }
    Column(Modifier.padding(top = 4.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        OutlinedTextField(
            value = extraKey,
            onValueChange = { extraKey = it },
            label = { Text("Extra key (optional)", fontSize = 9.sp) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = extraValue,
            onValueChange = { extraValue = it },
            label = { Text("Extra value", fontSize = 9.sp) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = deepLink,
            onValueChange = { deepLink = it },
            label = { Text("Data URI / deep link (optional)", fontSize = 9.sp) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        TextButton(
            onClick = {
                val launch = launcher.launch(target, extraKey, extraValue, deepLink)
                onNote("${launch.status.name}: ${launch.detail}")
            },
            contentPadding = androidx.compose.foundation.layout.PaddingValues(0.dp)
        ) { Text("Launch with these values", fontSize = 9.sp) }
    }
}

@Composable
private fun FuzzResultCard(result: FuzzResult) {
    Card(colors = CardDefaults.cardColors(containerColor = WorkbenchCard)) {
        Column(Modifier.padding(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    result.status.name,
                    fontSize = 8.sp,
                    color = Color(0xFF10171C),
                    modifier = Modifier
                        .background(fuzzStatusColor(result.status), RoundedCornerShape(4.dp))
                        .padding(horizontal = 4.dp, vertical = 2.dp)
                )
                Spacer(Modifier.size(6.dp))
                Text(
                    result.target.name,
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = AccentInfo,
                    modifier = Modifier.weight(1f)
                )
            }
            FactRow("Payload", result.payloadId, monospace = true)
            FactRow("Latency", result.latencyMs.toString() + " ms")
            Text(
                result.detail,
                fontSize = 9.sp,
                fontFamily = FontFamily.Monospace,
                color = MonoGray,
                modifier = Modifier.padding(top = 2.dp)
            )
            result.crash?.let { crash ->
                Text(
                    "Crash: ${crash.summary()}",
                    fontSize = 9.sp,
                    color = AccentBad,
                    modifier = Modifier.padding(top = 3.dp)
                )
            }
        }
    }
}

private fun fuzzStatusColor(status: FuzzStatus): Color = when (status) {
    FuzzStatus.CRASH -> AccentBad
    FuzzStatus.ERROR -> AccentWarn
    FuzzStatus.TIMEOUT -> AccentWarn
    FuzzStatus.BLOCKED -> AccentInfo
    FuzzStatus.SKIPPED -> MonoGray
    FuzzStatus.SENT -> AccentGood
}

@Composable
private fun ClassesTab(
    session: JadxSession?,
    loading: Boolean,
    error: String,
    onRetry: () -> Unit
) {
    when {
        loading -> Row(
            Modifier.fillMaxSize().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
            Text("Loading DEX classes with jadx 1.4.7...", fontSize = 12.sp)
        }
        error.isNotEmpty() -> Column(Modifier.padding(12.dp)) {
            Text("Class browser failed: $error", fontSize = 11.sp, color = AccentBad)
            OutlinedButton(onClick = onRetry, modifier = Modifier.padding(top = 8.dp)) {
                Text("Retry")
            }
        }
        session == null -> EmptyState("The class browser is not loaded.")
        else -> ClassBrowser(session)
    }
}

@Composable
private fun ClassBrowser(session: JadxSession) {
    var query by rememberSaveable { mutableStateOf("") }
    var selectedClass by rememberSaveable { mutableStateOf<String?>(null) }
    val selected = selectedClass
    if (selected != null) {
        ClassSourceView(session, selected) { selectedClass = null }
        return
    }
    val filtered = remember(query, session) {
        val needle = query.trim()
        if (needle.isEmpty()) session.classes
        else session.classes.filter { it.fullName.contains(needle, ignoreCase = true) }
    }
    LazyColumn(
        Modifier.fillMaxSize().padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        item {
            FactCard {
                FactRow("Classes", session.classes.size.toString())
                FactRow("jadx errors", session.errorCount.toString())
                FactRow("jadx warnings", session.warningCount.toString())
                if (session.issues.isNotEmpty()) {
                    Text(
                        session.issues.joinToString("\n"),
                        fontSize = 9.sp,
                        color = AccentWarn
                    )
                }
            }
        }
        item {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("Filter classes", fontSize = 10.sp) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
        }
        if (filtered.isEmpty()) {
            item { EmptyState("No classes match the filter.") }
        } else {
            items(filtered, key = { info: JadxClassInfo -> info.fullName }) { info ->
                Card(colors = CardDefaults.cardColors(containerColor = WorkbenchCard)) {
                    Column(Modifier.fillMaxWidth().padding(8.dp)) {
                        Text(
                            info.fullName,
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            color = AccentInfo
                        )
                        Text(
                            (if (info.packageName.isEmpty()) "default package" else info.packageName) +
                                if (info.inner) "  nested" else "",
                            fontSize = 8.sp,
                            color = MonoGray
                        )
                        TextButton(
                            onClick = { selectedClass = info.fullName },
                            contentPadding = androidx.compose.foundation.layout.PaddingValues(0.dp)
                        ) {
                            Text("Open source", fontSize = 9.sp)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ClassSourceView(session: JadxSession, fullName: String, onBack: () -> Unit) {
    var source by remember(fullName) { mutableStateOf("") }
    var loadingSource by remember(fullName) { mutableStateOf(true) }
    var sourceError by remember(fullName) { mutableStateOf("") }
    LaunchedEffect(fullName, session) {
        loadingSource = true
        sourceError = ""
        try {
            source = withContext(Dispatchers.IO) { session.source(fullName) }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            sourceError = failure.message ?: failure.javaClass.simpleName
        } finally {
            loadingSource = false
        }
    }
    LazyColumn(
        Modifier.fillMaxSize().padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = onBack) { Text("Classes", fontSize = 10.sp) }
                Text(
                    fullName,
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = AccentInfo,
                    modifier = Modifier.weight(1f)
                )
            }
        }
        if (loadingSource) {
            item {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                    Text("Decompiling...", fontSize = 10.sp)
                }
            }
        } else if (sourceError.isNotEmpty()) {
            item { NoticeCard("Decompilation failed: $sourceError") }
        } else if (source.isEmpty()) {
            item { EmptyState("jadx produced no Java source for this class.") }
        } else {
            item {
                SelectionContainer {
                    Text(
                        source.take(MAX_SOURCE_CHARS),
                        fontSize = 9.sp,
                        fontFamily = FontFamily.Monospace,
                        color = Color(0xFFDCE5E2)
                    )
                }
            }
            if (source.length > MAX_SOURCE_CHARS) {
                item {
                    NoticeCard(
                        "Source display is capped at ${MAX_SOURCE_CHARS / 1000}k characters; " +
                            "the decompiler produced ${source.length} characters."
                    )
                }
            }
        }
    }
}

@Composable
private fun FindingsTab(analysis: ApkAnalysis) {
    LazyColumn(
        Modifier.fillMaxSize().padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        item { SectionTitle("Findings (${analysis.findings.size})") }
        if (analysis.errors.isNotEmpty()) {
            item {
                NoticeCard(
                    "Some inputs were unreadable; findings may be incomplete:\n" +
                        analysis.errors.joinToString("\n") { "- $it" }
                )
            }
        }
        if (analysis.findings.isEmpty()) {
            item { EmptyState("No findings from the implemented static checks.") }
        } else {
            items(
                analysis.findings,
                key = { finding -> finding.id + ":" + (finding.componentRef ?: "") }
            ) { finding ->
                FindingCard(finding)
            }
        }
    }
}

@Composable
private fun FindingCard(finding: Finding) {
    Card(colors = CardDefaults.cardColors(containerColor = WorkbenchCard)) {
        Column(Modifier.padding(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SeverityBadge(finding.severity)
                Spacer(Modifier.size(6.dp))
                Text(finding.title, fontSize = 11.sp, color = Color(0xFFDCE5E2))
            }
            Text(
                sourceLabel(finding.source),
                fontSize = 9.sp,
                color = MonoGray,
                modifier = Modifier.padding(top = 2.dp)
            )
            Text(
                finding.evidence,
                fontSize = 10.sp,
                fontFamily = FontFamily.Monospace,
                color = MonoGray,
                modifier = Modifier.padding(top = 3.dp)
            )
            finding.componentRef?.let { ref ->
                Text(
                    ref,
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    color = AccentInfo,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text,
        fontSize = 13.sp,
        color = AccentInfo,
        modifier = Modifier.padding(top = 4.dp)
    )
}

@Composable
private fun FactCard(content: @Composable ColumnScope.() -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = WorkbenchCard)) {
        Column(Modifier.padding(8.dp), content = content)
    }
}

@Composable
private fun FactRow(
    label: String,
    value: String,
    monospace: Boolean = false,
    valueColor: Color = Color(0xFFDCE5E2)
) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 1.dp),
        verticalAlignment = Alignment.Top
    ) {
        Text(
            label,
            fontSize = 10.sp,
            color = MonoGray,
            modifier = Modifier.width(130.dp)
        )
        Spacer(Modifier.size(4.dp))
        Text(
            value,
            fontSize = 10.sp,
            fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
            color = valueColor,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun NoticeCard(text: String) {
    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF2A2416))) {
        Text(
            text,
            fontSize = 10.sp,
            color = AccentWarn,
            modifier = Modifier.padding(8.dp)
        )
    }
}

@Composable
private fun EmptyState(text: String) {
    Text(
        text,
        fontSize = 11.sp,
        color = MonoGray,
        modifier = Modifier.fillMaxWidth().padding(8.dp)
    )
}

@Composable
private fun SeverityBadge(severity: Severity) {
    Text(
        severity.name,
        fontSize = 8.sp,
        color = Color(0xFF10171C),
        modifier = Modifier
            .background(severityColor(severity), RoundedCornerShape(4.dp))
            .padding(horizontal = 4.dp, vertical = 2.dp)
    )
}

private fun severityColor(severity: Severity): Color = when (severity) {
    Severity.CRITICAL -> Color(0xFFD32F2F)
    Severity.HIGH -> AccentBad
    Severity.MEDIUM -> AccentWarn
    Severity.LOW -> AccentInfo
    Severity.INFO -> MonoGray
}

private fun sourceLabel(source: FindingSource): String = when (source) {
    FindingSource.MANIFEST -> "Manifest"
    FindingSource.SECRET -> "Strings"
    FindingSource.NATIVE -> "Native"
    FindingSource.FLUTTER -> "Flutter"
    FindingSource.FILE_PROVIDER -> "FileProvider"
    FindingSource.SIGNING -> "Signing"
}

private fun flag(value: Boolean?): String = when (value) {
    true -> "true"
    false -> "false"
    null -> "not set"
}

private fun hex(value: Int): String = "0x" + Integer.toHexString(value)

private fun exportLabel(kind: ExportKind): String = when (kind) {
    ExportKind.EXPLICIT_EXPORTED -> "explicit exported"
    ExportKind.EXPLICIT_NOT_EXPORTED -> "explicit not exported"
    ExportKind.IMPLICIT_EXPORTED -> "implicit (filter, no android:exported)"
    ExportKind.DEFAULT_NOT_EXPORTED -> "default not exported"
}

private fun formatBytes(bytes: Long): String =
    String.format(Locale.US, "%,d bytes", bytes)

private fun formatDate(epochMillis: Long): String =
    SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(epochMillis))

private fun buildAuditRecord(
    sessionId: String,
    startedAt: Long,
    file: File,
    result: ApkAnalysis
): ApkAuditRecord {
    val counts = result.findings.groupingBy { it.severity }.eachCount()
    return ApkAuditRecord(
        sessionId = sessionId,
        startedAt = startedAt,
        finishedAt = System.currentTimeMillis(),
        fileName = file.name,
        packageName = result.manifest?.packageName,
        sha256 = result.sha256,
        sizeBytes = result.sizeBytes,
        findingCount = result.findings.size,
        criticalCount = counts[Severity.CRITICAL] ?: 0,
        highCount = counts[Severity.HIGH] ?: 0,
        mediumCount = counts[Severity.MEDIUM] ?: 0,
        lowCount = counts[Severity.LOW] ?: 0,
        infoCount = counts[Severity.INFO] ?: 0,
        truncated = result.truncated,
        errors = result.errors
    )
}

private fun recordAudit(context: Context, record: ApkAuditRecord): String {
    val store = ApkAuditStore(context)
    return try {
        store.record(record)
        ""
    } catch (failure: Exception) {
        "Audit log failed: ${failure.message ?: failure.javaClass.simpleName}"
    } finally {
        store.close()
    }
}
