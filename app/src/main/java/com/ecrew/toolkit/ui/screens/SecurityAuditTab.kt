package com.ecrew.toolkit.ui.screens

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.ecrew.toolkit.audit.AuditCategory
import com.ecrew.toolkit.audit.AuditCoordinator
import com.ecrew.toolkit.audit.AuditExport
import com.ecrew.toolkit.audit.AuditExportFinding
import com.ecrew.toolkit.audit.AuditExportSession
import com.ecrew.toolkit.audit.AuditScoring
import com.ecrew.toolkit.audit.AuditSessionRow
import com.ecrew.toolkit.audit.AuditShizuku
import com.ecrew.toolkit.audit.AuditStatus
import com.ecrew.toolkit.audit.RootState
import com.ecrew.toolkit.audit.ShellTier
import com.ecrew.toolkit.audit.ShizukuState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Security & privacy audit (Component 13), mounted as the "Audit" tab of the Forensics hub.
 *
 * Read-only scan driven by [AuditCoordinator]: score card, privileged setup card (ADB grants
 * plus the Shizuku state and its user-triggered permission request), sectioned findings with
 * evidence, Fix intents and mute toggles, Markdown/JSON export with "hide personal details",
 * and session history.
 */
@Composable
fun SecurityAuditTab() {
    val context = LocalContext.current
    val coordinator = remember(context) {
        AuditCoordinator(context.applicationContext)
    }
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    val timeFormat = remember { SimpleDateFormat("MM-dd HH:mm", Locale.US) }

    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("no scan yet - run a scan to build a baseline") }
    var session by remember { mutableStateOf<AuditExportSession?>(null) }
    var viewingHistory by remember { mutableStateOf(false) }
    var history by remember { mutableStateOf(listOf<AuditSessionRow>()) }
    var muted by remember { mutableStateOf(emptySet<String>()) }
    var hidePersonal by remember { mutableStateOf(true) }
    var privilegedTier by remember { mutableStateOf(ShellTier.NONE) }
    var shizukuState by remember { mutableStateOf(AuditShizuku.state(context)) }
    var rootOptIn by remember { mutableStateOf(false) }
    var rootState by remember { mutableStateOf(RootState.DISABLED) }
    var pendingExport by remember { mutableStateOf<AuditExport.Format?>(null) }

    fun reloadHistory() {
        scope.launch {
            history = withContext(Dispatchers.IO) { coordinator.history(8) }
        }
    }

    fun scan() {
        if (busy) return
        busy = true
        status = "scanning..."
        scope.launch {
            val outcome = withContext(Dispatchers.IO) { coordinator.run() }
            val result = outcome.getOrNull()
            if (result == null) {
                status = "scan failed: " +
                    (outcome.exceptionOrNull()?.message ?: "unknown error")
            } else {
                session = AuditExportSession.from(result)
                viewingHistory = false
                muted = withContext(Dispatchers.IO) { coordinator.mutedIds() }
                status = "scan finished: ${result.report.findings.size} checks in " +
                    "${result.finishedAt - result.startedAt} ms"
            }
            busy = false
            history = withContext(Dispatchers.IO) { coordinator.history(8) }
        }
    }

    fun recheckTier() {
        if (busy) return
        busy = true
        scope.launch {
            val snapshot = withContext(Dispatchers.IO) { coordinator.recheckTier() }
            privilegedTier = snapshot.tier
            shizukuState = snapshot.shizuku
            rootState = snapshot.root
            busy = false
            status = when (snapshot.tier) {
                ShellTier.ROOT ->
                    "Root tier active: all 54 checks run through the opt-in root shell"
                ShellTier.SHIZUKU ->
                    "Shizuku tier active: the 8 ADB checks and the 3 Shizuku checks run through it"
                ShellTier.ADB ->
                    "ADB tier active: the dumpsys checks run with both grants"
                ShellTier.NONE -> when {
                    snapshot.root == RootState.NOT_AVAILABLE ->
                        "no privileged tier: root opt-in is on, but su is not available to E-Crew"
                    snapshot.root == RootState.DENIED ->
                        "no privileged tier: root opt-in is on, but su did not return uid 0"
                    snapshot.shizuku == ShizukuState.NOT_INSTALLED ->
                        "no privileged tier: Shizuku is not installed and DUMP is not granted"
                    snapshot.shizuku == ShizukuState.NOT_RUNNING ->
                        "no privileged tier: Shizuku is installed but not running; DUMP is not granted"
                    snapshot.shizuku == ShizukuState.PERMISSION_REQUIRED ->
                        "no privileged tier: Shizuku is running but E-Crew is not granted"
                    snapshot.shizuku == ShizukuState.READY ->
                        "Shizuku is granted but the shell is not ready; recheck after a scan"
                    else ->
                        "no privileged tier: enable root checks, start Shizuku or grant DUMP"
                }
            }
        }
    }

    fun toggleRootOptIn(enabled: Boolean) {
        if (busy) return
        busy = true
        scope.launch {
            val snapshot = withContext(Dispatchers.IO) {
                coordinator.setRootOptIn(enabled)
                coordinator.recheckTier()
            }
            rootOptIn = enabled
            privilegedTier = snapshot.tier
            shizukuState = snapshot.shizuku
            rootState = snapshot.root
            busy = false
            status = if (!enabled) {
                "root checks disabled - the next scan uses the remaining tiers"
            } else {
                when (snapshot.root) {
                    RootState.READY ->
                        "root tier active - run a scan for the 54-check baseline"
                    RootState.NOT_AVAILABLE ->
                        "root opt-in saved, but su is not available to E-Crew; the 4 root checks stay N/A"
                    RootState.DENIED ->
                        "root opt-in saved, but su did not return uid 0; the 4 root checks stay N/A"
                    RootState.DISABLED -> "root opt-in saved"
                }
            }
        }
    }

    fun requestShizuku() {
        val requested = coordinator.requestShizukuPermission()
        status = if (requested) {
            "Shizuku permission requested - answer the Shizuku prompt"
        } else {
            "could not request Shizuku access; is Shizuku running?"
        }
    }

    fun openSession(row: AuditSessionRow) {
        scope.launch {
            val loaded = withContext(Dispatchers.IO) { coordinator.loadSession(row.id) }
            if (loaded == null) {
                status = "session ${row.id.take(8)} has no stored report"
            } else {
                session = loaded
                viewingHistory = true
                status = "viewing session from ${timeFormat.format(Date(row.startedAt))}"
            }
        }
    }

    fun toggleMute(id: String) {
        val next = id !in muted
        scope.launch {
            withContext(Dispatchers.IO) { coordinator.setMuted(id, next) }
            muted = if (next) muted + id else muted - id
            status = if (next) {
                "muted $id - takes full effect on the next scan"
            } else {
                "unmuted $id"
            }
        }
    }

    fun unmuteAll() {
        scope.launch {
            withContext(Dispatchers.IO) { coordinator.clearMutes() }
            muted = emptySet()
            status = "all mutes cleared"
        }
    }

    fun openFix(action: String) {
        try {
            context.startActivity(Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            status = "opened Settings action $action"
        } catch (e: ActivityNotFoundException) {
            status = "no Settings screen handles $action on this device"
        }
    }

    fun doExport(format: AuditExport.Format) {
        val current = session
        if (current == null) {
            status = "nothing to export - run a scan first"
            return
        }
        if (busy) return
        busy = true
        status = "writing ${format.name.lowercase(Locale.US)} export..."
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                coordinator.export(current, format, hidePersonal)
            }
            status = if (result.isSuccess) {
                "exported: ${result.getOrNull()}"
            } else {
                "export failed: ${result.exceptionOrNull()?.message ?: "unknown error"}"
            }
            busy = false
        }
    }

    val storageLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        val format = pendingExport
        pendingExport = null
        when {
            !granted -> status = "storage permission denied - export cancelled"
            format != null -> doExport(format)
        }
    }

    fun export(format: AuditExport.Format) {
        if (session == null) {
            status = "nothing to export - run a scan first"
            return
        }
        val needsLegacyPermission = Build.VERSION.SDK_INT < 29 &&
            ContextCompat.checkSelfPermission(
                context, Manifest.permission.WRITE_EXTERNAL_STORAGE
            ) != PackageManager.PERMISSION_GRANTED
        if (needsLegacyPermission) {
            pendingExport = format
            status = "requesting storage permission..."
            storageLauncher.launch(Manifest.permission.WRITE_EXTERNAL_STORAGE)
        } else {
            doExport(format)
        }
    }

    LaunchedEffect(Unit) {
        hidePersonal = withContext(Dispatchers.IO) { coordinator.hidePersonalDetails() }
        muted = withContext(Dispatchers.IO) { coordinator.mutedIds() }
        rootOptIn = withContext(Dispatchers.IO) { coordinator.rootOptIn() }
        val tier = withContext(Dispatchers.IO) { coordinator.privilegedTier() }
        val state = withContext(Dispatchers.IO) { coordinator.shizukuState() }
        val root = withContext(Dispatchers.IO) { coordinator.rootState() }
        privilegedTier = tier
        shizukuState = state
        rootState = root
        val rows = withContext(Dispatchers.IO) { coordinator.history(8) }
        history = rows
        val newest = rows.firstOrNull()
        if (newest != null) {
            session = withContext(Dispatchers.IO) { coordinator.loadSession(newest.id) }
            if (session != null) {
                viewingHistory = true
                status = "loaded the newest stored session; run a scan for a fresh baseline"
            }
        }
    }

    // The Shizuku permission answer arrives on a binder thread; update the card on the main
    // thread and keep a trail entry. The listener is removed when the tab leaves the screen.
    DisposableEffect(Unit) {
        val listener = AuditShizuku.addPermissionResultListener { granted ->
            scope.launch {
                withContext(Dispatchers.IO) { coordinator.logShizukuPermission(granted) }
                shizukuState = withContext(Dispatchers.IO) { coordinator.shizukuState() }
                privilegedTier = withContext(Dispatchers.IO) { coordinator.privilegedTier() }
                status = if (granted) {
                    "Shizuku access granted - run a scan for the 54-check baseline"
                } else {
                    "Shizuku access denied - the three Shizuku checks stay N/A"
                }
            }
        }
        onDispose { AuditShizuku.removePermissionResultListener(listener) }
    }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(8.dp)
    ) {
        Text(
            "Security & privacy audit",
            style = MaterialTheme.typography.titleMedium,
            color = AccentInfo
        )
        Spacer(Modifier.height(4.dp))
        Text(
            "Read-only device audit: 54 checks run locally (39 Base + 8 ADB + 3 Shizuku + 4 " +
                "Root, the last opt-in). The app never changes a setting - Fix buttons only " +
                "open the matching Settings screen.",
            fontSize = 11.sp,
            color = MonoGray
        )
        Spacer(Modifier.height(8.dp))
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Button(onClick = { scan() }, enabled = !busy) { Text("Run scan") }
            Text(
                status,
                fontSize = 10.sp,
                color = if (busy) AccentWarn else MonoGray
            )
        }
        if (muted.isNotEmpty()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (muted.size == 1) "1 check muted" else "${muted.size} checks muted",
                    fontSize = 10.sp,
                    color = AccentWarn
                )
                Spacer(Modifier.width(8.dp))
                TextButton(onClick = { unmuteAll() }, enabled = !busy) {
                    Text("Unmute all", fontSize = 11.sp)
                }
            }
        }
        Spacer(Modifier.height(8.dp))

        val current = session
        if (current == null) {
            Text(
                "No report to show yet. Run a scan; every session is stored locally so it " +
                    "can be exported or compared later.",
                fontSize = 11.sp,
                color = MonoGray
            )
        } else {
            if (viewingHistory) {
                Text(
                    "Viewing a stored session (${timeFormat.format(Date(current.startedAt))}).",
                    fontSize = 10.sp,
                    color = AccentWarn
                )
                Spacer(Modifier.height(4.dp))
            }
            ScoreCard(current, muted)
            Spacer(Modifier.height(8.dp))
        }

        TierCard(
            privilegedTier = privilegedTier,
            shizukuState = shizukuState,
            rootOptIn = rootOptIn,
            rootState = rootState,
            busy = busy,
            packageName = context.packageName,
            onCopy = { command ->
                clipboard.setText(AnnotatedString(command))
                status = "command copied"
            },
            onRecheck = { recheckTier() },
            onRequestShizuku = { requestShizuku() },
            onRootOptIn = { enabled -> toggleRootOptIn(enabled) }
        )

        if (current != null) {
            Spacer(Modifier.height(8.dp))
            ExportCard(
                hidePersonal = hidePersonal,
                enabled = !busy,
                onToggle = { value ->
                    hidePersonal = value
                    scope.launch {
                        withContext(Dispatchers.IO) { coordinator.setHidePersonalDetails(value) }
                        status = if (value) {
                            "personal details are hidden in exports"
                        } else {
                            "personal details are exported verbatim - share carefully"
                        }
                    }
                },
                onExport = { format -> export(format) }
            )
            Spacer(Modifier.height(8.dp))
            FindingsSection(current, muted, onFix = { openFix(it) }, onToggleMute = { toggleMute(it) })
        }

        Spacer(Modifier.height(10.dp))
        Text("History", fontSize = 12.sp, color = AccentInfo)
        if (history.isEmpty()) {
            Text("No stored sessions.", fontSize = 10.sp, color = MonoGray)
        } else {
            history.forEach { row ->
                HistoryRow(
                    row = row,
                    selected = row.id == current?.sessionId,
                    timeFormat = timeFormat,
                    onClick = { openSession(row) }
                )
            }
        }
        Spacer(Modifier.height(12.dp))
    }
}

@Composable
private fun ScoreCard(session: AuditExportSession, muted: Set<String>) {
    val score = AuditScoring.computeExport(session.findings, muted)
    val counts = remember(session, muted) {
        val map = LinkedHashMap<AuditStatus, Int>()
        for (value in AuditStatus.values()) map[value] = 0
        for (finding in session.findings) {
            val shown = if (finding.id in muted) AuditStatus.MUTED else finding.status
            map[shown] = map.getValue(shown) + 1
        }
        map
    }
    val scoreColor = when {
        !score.isScored -> MonoGray
        score.score >= 80 -> AccentGood
        score.score >= 50 -> AccentWarn
        else -> AccentBad
    }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (score.isScored) "${score.score}" else "N/S",
                    fontSize = 34.sp,
                    color = scoreColor
                )
                Spacer(Modifier.width(8.dp))
                Column {
                    Text(
                        if (score.isScored) "score / 100" else "not scored (no scored checks)",
                        fontSize = 12.sp,
                        color = MonoGray
                    )
                    Text(
                        "passed weight ${score.passedWeight} of ${score.scoredWeight}",
                        fontSize = 10.sp,
                        color = MonoGray
                    )
                    if (score.criticalCapApplied) {
                        Text(
                            "capped at 40: a critical finding failed or warned",
                            fontSize = 10.sp,
                            color = AccentBad
                        )
                    }
                    Text(
                        "privileged tier: ${tierLabel(session.privilegedTier)}",
                        fontSize = 10.sp,
                        color = if (session.privilegedTier != ShellTier.NONE) {
                            AccentGood
                        } else {
                            MonoGray
                        }
                    )
                }
            }
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                for (value in AuditStatus.values()) {
                    Text(
                        "${statusLabel(value)} ${counts.getValue(value)}",
                        fontSize = 10.sp,
                        color = statusColor(value)
                    )
                }
            }
            Spacer(Modifier.height(4.dp))
            Text(
                "UNKNOWN and N/A never count as a pass; muted checks leave the score.",
                fontSize = 9.sp,
                color = MonoGray
            )
        }
    }
}

@Composable
private fun TierCard(
    privilegedTier: ShellTier,
    shizukuState: ShizukuState,
    rootOptIn: Boolean,
    rootState: RootState,
    busy: Boolean,
    packageName: String,
    onCopy: (String) -> Unit,
    onRecheck: () -> Unit,
    onRequestShizuku: () -> Unit,
    onRootOptIn: (Boolean) -> Unit
) {
    val dumpCommand = "adb shell pm grant $packageName android.permission.DUMP"
    val usageCommand =
        "adb shell pm grant $packageName android.permission.PACKAGE_USAGE_STATS"
    val adbLabel = when (privilegedTier) {
        ShellTier.ROOT -> "covered by Root"
        ShellTier.SHIZUKU -> "covered by Shizuku"
        ShellTier.ADB -> "active"
        ShellTier.NONE -> "inactive"
    }
    val adbColor = if (privilegedTier == ShellTier.NONE) AccentWarn else AccentGood
    val shizukuLabel = when (shizukuState) {
        ShizukuState.READY -> "active"
        ShizukuState.PERMISSION_REQUIRED -> "running, access not granted"
        ShizukuState.NOT_RUNNING -> "not running"
        ShizukuState.NOT_INSTALLED -> "not installed"
    }
    val shizukuColor = when (shizukuState) {
        ShizukuState.READY -> AccentGood
        ShizukuState.NOT_INSTALLED -> MonoGray
        else -> AccentWarn
    }
    val rootLabel = when (rootState) {
        RootState.READY -> "active"
        RootState.NOT_AVAILABLE -> "su unavailable"
        RootState.DENIED -> "su denied"
        RootState.DISABLED -> "opt-in off"
    }
    val rootColor = when (rootState) {
        RootState.READY -> AccentGood
        RootState.DISABLED -> MonoGray
        else -> AccentWarn
    }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Privileged tiers", style = MaterialTheme.typography.titleSmall)
                Spacer(Modifier.width(8.dp))
                TextButton(onClick = onRecheck, enabled = !busy) { Text("Recheck") }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("ADB tier", fontSize = 12.sp, modifier = Modifier.weight(1f))
                Text(adbLabel, fontSize = 11.sp, color = adbColor)
            }
            if (privilegedTier == ShellTier.SHIZUKU || privilegedTier == ShellTier.ROOT) {
                Text(
                    "The 8 ADB checks run through the active privileged tier, so no DUMP " +
                        "grant is needed while it is active.",
                    fontSize = 9.sp,
                    color = MonoGray
                )
            }
            Spacer(Modifier.height(4.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Shizuku tier", fontSize = 12.sp, modifier = Modifier.weight(1f))
                Text(shizukuLabel, fontSize = 11.sp, color = shizukuColor)
            }
            Text(
                when (shizukuState) {
                    ShizukuState.READY ->
                        "SELinux mode, always-on VPN lockdown and the SIM check are enabled; " +
                            "the Smart Lock read also runs as the served user."
                    ShizukuState.PERMISSION_REQUIRED ->
                        "Shizuku is running. Tap Request access and allow E-Crew in the " +
                            "Shizuku prompt; nothing is requested until you tap."
                    ShizukuState.NOT_RUNNING ->
                        "Shizuku is installed but stopped. Android 8 has no wireless " +
                            "debugging: start it once from a PC with the command the Shizuku " +
                            "app shows, then recheck."
                    ShizukuState.NOT_INSTALLED ->
                        "Install the Shizuku app yourself to enable the 3 Shizuku checks and " +
                            "the Smart Lock read; E-Crew never bundles, downloads or starts it."
                },
                fontSize = 9.sp,
                color = MonoGray
            )
            if (shizukuState == ShizukuState.PERMISSION_REQUIRED &&
                privilegedTier != ShellTier.ROOT
            ) {
                Spacer(Modifier.height(4.dp))
                OutlinedButton(onClick = onRequestShizuku, enabled = !busy) {
                    Text("Request access")
                }
            }
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Root tier", fontSize = 12.sp, modifier = Modifier.weight(1f))
                Text(rootLabel, fontSize = 11.sp, color = rootColor)
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "Enable root checks (opt-in)",
                    fontSize = 11.sp,
                    modifier = Modifier.weight(1f)
                )
                Switch(
                    checked = rootOptIn,
                    onCheckedChange = onRootOptIn,
                    enabled = !busy
                )
            }
            Text(
                "E-Crew runs 4 extra checks through your root manager with fixed read-only " +
                    "commands (id, cat, ls, ss). A root prompt may appear when you enable this. " +
                    "E-Crew never bundles, downloads or grants root and never changes a setting.",
                fontSize = 9.sp,
                color = MonoGray
            )
            if (rootOptIn && rootState != RootState.READY) {
                Text(
                    when (rootState) {
                        RootState.NOT_AVAILABLE ->
                            "su is not reachable by E-Crew: either no root manager is active " +
                                "for this app, or the su binary refuses app UIDs. The 4 root " +
                                "checks stay N/A; nothing is bypassed."
                        RootState.DENIED ->
                            "su ran but did not return uid 0, so the tier stays inactive and " +
                                "the 4 root checks stay N/A."
                        else ->
                            "The root probe has not returned yet; tap Recheck on a rooted device."
                    },
                    fontSize = 9.sp,
                    color = AccentWarn
                )
            }
            if (privilegedTier == ShellTier.ROOT) {
                Text(
                    "All 54 checks run through the root shell; the ADB and Shizuku checks are " +
                        "included.",
                    fontSize = 9.sp,
                    color = AccentGood
                )
            }
            if (privilegedTier == ShellTier.NONE) {
                Spacer(Modifier.height(6.dp))
                Text(
                    "ADB alternative - run both commands once from a PC with USB debugging; " +
                        "the grants survive reboots and can be revoked with pm revoke. DUMP is " +
                        "a development permission and some builds refuse the grant - then the " +
                        "checks stay N/A.",
                    fontSize = 10.sp,
                    color = MonoGray
                )
                Spacer(Modifier.height(6.dp))
                GrantCommand(dumpCommand, onCopy, busy)
                Spacer(Modifier.height(4.dp))
                GrantCommand(usageCommand, onCopy, busy)
            }
        }
    }
}

@Composable
private fun GrantCommand(command: String, onCopy: (String) -> Unit, busy: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(
            command,
            fontSize = 9.sp,
            fontFamily = FontFamily.Monospace,
            color = MonoGray,
            modifier = Modifier.weight(1f)
        )
        TextButton(onClick = { onCopy(command) }, enabled = !busy) { Text("Copy") }
    }
}

@Composable
private fun ExportCard(
    hidePersonal: Boolean,
    enabled: Boolean,
    onToggle: (Boolean) -> Unit,
    onExport: (AuditExport.Format) -> Unit
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(10.dp)) {
            Text("Export", style = MaterialTheme.typography.titleSmall)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(checked = hidePersonal, onCheckedChange = onToggle, enabled = enabled)
                Spacer(Modifier.width(8.dp))
                Text(
                    "Hide personal details (IP addresses, proxy/DNS servers, hostnames)",
                    fontSize = 10.sp,
                    color = MonoGray
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { onExport(AuditExport.Format.MARKDOWN) },
                    enabled = enabled
                ) { Text("Export Markdown") }
                OutlinedButton(
                    onClick = { onExport(AuditExport.Format.JSON) },
                    enabled = enabled
                ) { Text("Export JSON") }
            }
            Text(
                "Writes to Downloads/${AuditExport.FOLDER}/; if the system blocks that " +
                    "path, the app-specific folder on the same storage is used and the " +
                    "exact path is shown. The export is also noted in the session audit trail.",
                fontSize = 9.sp,
                color = MonoGray
            )
        }
    }
}

@Composable
private fun FindingsSection(
    session: AuditExportSession,
    muted: Set<String>,
    onFix: (String) -> Unit,
    onToggleMute: (String) -> Unit
) {
    Text("Findings", fontSize = 12.sp, color = AccentInfo)
    Spacer(Modifier.height(4.dp))
    for (category in AuditCategory.values()) {
        val findings = session.findings.filter { it.category == category }
        if (findings.isNotEmpty()) {
            CategoryBlock(category, findings, muted, onFix, onToggleMute)
        }
    }
    Spacer(Modifier.height(6.dp))
    Divider(color = Color(0xFF263238))
}

@Composable
private fun CategoryBlock(
    category: AuditCategory,
    findings: List<AuditExportFinding>,
    muted: Set<String>,
    onFix: (String) -> Unit,
    onToggleMute: (String) -> Unit
) {
    Text(category.label, fontSize = 11.sp, color = AccentInfo)
    Spacer(Modifier.height(2.dp))
    for (finding in findings) {
        val shown = if (finding.id in muted) AuditStatus.MUTED else finding.status
        FindingCard(
            finding = finding,
            shownStatus = shown,
            muted = finding.id in muted,
            onFix = onFix,
            onToggleMute = onToggleMute
        )
        Spacer(Modifier.height(3.dp))
    }
    Spacer(Modifier.height(4.dp))
}

@Composable
private fun FindingCard(
    finding: AuditExportFinding,
    shownStatus: AuditStatus,
    muted: Boolean,
    onFix: (String) -> Unit,
    onToggleMute: (String) -> Unit
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    statusLabel(shownStatus),
                    fontSize = 10.sp,
                    color = statusColor(shownStatus)
                )
                Spacer(Modifier.width(6.dp))
                Text("${finding.id} ${finding.title}", fontSize = 12.sp)
            }
            Text(
                "${finding.severity.name} (weight ${finding.severity.weight}) / ${finding.tier.name}",
                fontSize = 9.sp,
                color = MonoGray
            )
            Spacer(Modifier.height(2.dp))
            Text(
                finding.evidence,
                fontSize = 10.sp,
                fontFamily = FontFamily.Monospace,
                color = MonoGray
            )
            Text(finding.explanation, fontSize = 10.sp, color = MonoGray)
            val fix = finding.fixAction
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (fix != null) {
                    TextButton(onClick = { onFix(fix) }) {
                        Text("Fix: open Settings", fontSize = 11.sp)
                    }
                }
                TextButton(onClick = { onToggleMute(finding.id) }) {
                    Text(if (muted) "Unmute" else "Mute", fontSize = 11.sp)
                }
            }
        }
    }
}

@Composable
private fun HistoryRow(
    row: AuditSessionRow,
    selected: Boolean,
    timeFormat: SimpleDateFormat,
    onClick: () -> Unit
) {
    Text(
        "${timeFormat.format(Date(row.startedAt))}  " +
            (if (row.score == null) {
                "unfinished"
            } else if (row.notScored) {
                "not scored"
            } else {
                "score ${row.score}/100"
            }) +
            "  (${row.checksRun} checks" +
            (if (row.privilegedTier != ShellTier.NONE) {
                ", ${row.privilegedTier.name.lowercase(Locale.US)}"
            } else {
                ""
            }) + ")" +
            if (selected) "  <- shown" else "",
        fontSize = 10.sp,
        color = if (selected) AccentInfo else MonoGray,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 3.dp)
    )
}

private fun statusColor(status: AuditStatus): Color = when (status) {
    AuditStatus.PASS -> AccentGood
    AuditStatus.FAIL -> AccentBad
    AuditStatus.WARN -> AccentWarn
    AuditStatus.UNKNOWN, AuditStatus.NA, AuditStatus.MUTED -> MonoGray
}

private fun statusLabel(status: AuditStatus): String =
    if (status == AuditStatus.NA) "N/A" else status.name

private fun tierLabel(tier: ShellTier): String = when (tier) {
    ShellTier.NONE -> "none (Base only)"
    ShellTier.ADB -> "ADB"
    ShellTier.SHIZUKU -> "Shizuku"
    ShellTier.ROOT -> "Root"
}
