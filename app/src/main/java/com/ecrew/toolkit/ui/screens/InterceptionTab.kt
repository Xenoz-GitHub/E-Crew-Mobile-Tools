package com.ecrew.toolkit.ui.screens

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.ecrew.toolkit.audit.AuditShizuku
import com.ecrew.toolkit.audit.AuditStore
import com.ecrew.toolkit.audit.ShizukuState
import com.ecrew.toolkit.intercept.FridaScripts
import com.ecrew.toolkit.intercept.GeneratedScript
import com.ecrew.toolkit.intercept.InterceptionAudit
import com.ecrew.toolkit.intercept.InterceptionBus
import com.ecrew.toolkit.intercept.InterceptionConsent
import com.ecrew.toolkit.intercept.InterceptionProxyService
import com.ecrew.toolkit.intercept.LocalProxyServer
import com.ecrew.toolkit.intercept.PinningGuides
import com.ecrew.toolkit.intercept.ProxyLogEntry
import com.ecrew.toolkit.intercept.ShizukuProxyController
import com.ecrew.toolkit.intercept.UpstreamConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val IntCard = Color(0xFF161C22)
private val IntLine = Color(0xFF263238)
private val IntMuted = Color(0xFF8FA3A8)
private val IntGood = Color(0xFF58D68D)
private val IntWarn = Color(0xFFF4D03F)
private val IntBad = Color(0xFFFF6B6B)
private val IntInfo = Color(0xFF7FB3D5)

@Composable
fun InterceptionTab() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var consentAt by remember { mutableStateOf(readConsent(context)) }
    var statementChecked by remember { mutableStateOf(false) }
    var consentError by remember { mutableStateOf("") }
    val sessionId = remember { InterceptionAudit.newSessionId() }

    if (consentAt == null) {
        Column(
            Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("Interception consent", color = IntWarn, fontSize = 17.sp)
            Text(
                "This module can relay app traffic through an interception proxy and can " +
                    "change the device-wide HTTP proxy through Shizuku. It never installs a " +
                    "CA, never bundles Frida, and never silently changes a proxy.",
                color = IntMuted,
                fontSize = 11.sp
            )
            Text(InterceptionConsent.STATEMENT, color = IntInfo, fontSize = 12.sp)
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                Checkbox(
                    checked = statementChecked,
                    onCheckedChange = { statementChecked = it }
                )
                Text(
                    "I have read the statement and have authorization for this device and app.",
                    fontSize = 10.sp
                )
            }
            Text(
                "The proxy log is memory-only. Sensitive header values are redacted. Body " +
                    "contents are never logged.",
                color = IntMuted,
                fontSize = 9.sp
            )
            Button(
                onClick = {
                    val store = AuditStore(context)
                    try {
                        consentAt = InterceptionConsent.confirm(context, store, sessionId)
                        consentError = ""
                    } catch (failure: Exception) {
                        consentError = failure.message ?: failure.javaClass.simpleName
                    } finally {
                        store.close()
                    }
                },
                enabled = statementChecked
            ) { Text("Record consent and continue", fontSize = 10.sp) }
            if (consentError.isNotEmpty()) Text(consentError, color = IntBad, fontSize = 10.sp)
        }
        return
    }

    var tick by remember { mutableIntStateOf(0) }
    var upstreamText by remember { mutableStateOf(readUpstream(context)) }
    var localError by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("") }
    var globalError by remember { mutableStateOf("") }
    var globalWarning by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var scripts by remember { mutableStateOf<List<GeneratedScript>>(emptyList()) }
    var fridaError by remember { mutableStateOf("") }
    val shizukuReady = AuditShizuku.state(context) == ShizukuState.READY

    LaunchedEffect(tick) {
        delay(500)
        tick++
    }

    LazyColumn(
        Modifier.fillMaxSize().padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        item {
            Text("Authorized interception support", color = IntInfo, fontSize = 15.sp)
            Text(
                "The on-device proxy listens only on ${LocalProxyServer.DEFAULT_PORT} loopback. " +
                    "It does not terminate TLS; an operator-run Burp/mitmproxy owns the CA and " +
                    "the certificate the target app sees.",
                fontSize = 10.sp,
                color = IntMuted
            )
            Text(
                "The PCAP module remains the primary evidence path. This module is for " +
                    "authorized active testing.",
                fontSize = 9.sp,
                color = IntMuted
            )
            Text(
                "Consent recorded at ${formatTime(consentAt ?: 0)}. It is audit-logged.",
                fontSize = 8.sp,
                color = IntMuted
            )
            TextButton(onClick = {
                InterceptionProxyService.stop(context)
                val store = AuditStore(context)
                try {
                    InterceptionConsent.revoke(store)
                } finally {
                    store.close()
                }
                InterceptionAudit.append(context, sessionId, "consent_revoked")
                consentAt = null
            }) { Text("Revoke interception consent", fontSize = 8.sp, color = IntBad) }
        }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = IntCard)) {
                Column(Modifier.padding(10.dp)) {
                    Text("Local proxy", fontSize = 12.sp, color = IntInfo)
                    val boundPort = InterceptionBus.boundPort.let {
                        if (it == 0) LocalProxyServer.DEFAULT_PORT else it
                    }
                    Text(
                        if (InterceptionBus.running) {
                            "Listening: 127.0.0.1:$boundPort"
                        } else {
                            "Bind target: 127.0.0.1:$boundPort (not listening)"
                        },
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        "Upstream: ${InterceptionBus.upstream ?: "direct (no upstream)"}",
                        fontSize = 9.sp,
                        color = IntMuted
                    )
                    OutlinedTextField(
                        value = upstreamText,
                        onValueChange = { upstreamText = it },
                        label = { Text("Upstream host:port (Burp/mitmproxy)", fontSize = 9.sp) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().padding(top = 4.dp)
                    )
                    Row(
                        Modifier.padding(top = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = {
                                localError = ""
                                try {
                                    if (upstreamText.isNotBlank()) {
                                        val parsed = UpstreamConfig.parse(upstreamText)
                                        val store = AuditStore(context)
                                        try {
                                            UpstreamConfig.save(store, parsed)
                                        } finally {
                                            store.close()
                                        }
                                        InterceptionAudit.append(
                                            context,
                                            sessionId,
                                            "upstream_change",
                                            mapOf("upstream" to parsed.display)
                                        )
                                    }
                                    InterceptionProxyService.start(
                                        context,
                                        LocalProxyServer.DEFAULT_PORT,
                                        upstreamText.takeIf { it.isNotBlank() },
                                        sessionId
                                    )
                                    status = "Proxy start requested."
                                } catch (failure: Exception) {
                                    localError = failure.message ?: failure.javaClass.simpleName
                                }
                            },
                            enabled = !InterceptionBus.running
                        ) { Text("Start local proxy", fontSize = 9.sp) }
                        OutlinedButton(
                            onClick = {
                                InterceptionProxyService.stop(context)
                                status = "Proxy stop requested."
                            },
                            enabled = InterceptionBus.running
                        ) { Text("Stop", fontSize = 9.sp) }
                    }
                    InterceptionBus.error?.let {
                        Text(it, fontSize = 9.sp, color = IntBad, modifier = Modifier.padding(top = 4.dp))
                    }
                    if (localError.isNotEmpty()) Text(localError, fontSize = 9.sp, color = IntBad)
                    if (status.isNotEmpty()) Text(status, fontSize = 8.sp, color = IntMuted)
                }
            }
        }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = IntCard)) {
                Column(Modifier.padding(10.dp)) {
                    Text("Device-wide proxy (Shizuku)", fontSize = 12.sp, color = IntWarn)
                    Text(
                        "Changing the global proxy affects every app and can break network " +
                            "connectivity. This uses a dedicated Shizuku user service, only after " +
                            "the warning below is acknowledged. The old value is captured first " +
                            "and restored on Stop.",
                        fontSize = 9.sp,
                        color = IntMuted
                    )
                    Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                        Checkbox(
                            checked = globalWarning,
                            onCheckedChange = { globalWarning = it }
                        )
                        Text(
                            "I understand this is a device-wide change and I am authorized.",
                            fontSize = 9.sp
                        )
                    }
                    Text(
                        if (shizukuReady) {
                            "Shizuku ready. Global proxy target will be 127.0.0.1:${LocalProxyServer.DEFAULT_PORT}."
                        } else {
                            "Shizuku is not ready. Use the manual guide below; the app will not " +
                                "change the proxy."
                        },
                        fontSize = 9.sp,
                        color = if (shizukuReady) IntGood else IntWarn
                    )
                    Row(
                        Modifier.padding(top = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = {
                                globalError = ""
                                busy = true
                                scope.launch {
                                    val controller = ShizukuProxyController(context)
                                    try {
                                        val result = withContext(Dispatchers.IO) {
                                            controller.apply("127.0.0.1", LocalProxyServer.DEFAULT_PORT)
                                        }
                                        if (result.success) {
                                            InterceptionBus.globalProxyApplied = true
                                            InterceptionBus.globalProxyPrevious = result.previous
                                            InterceptionAudit.append(
                                                context,
                                                sessionId,
                                                "global_proxy_set",
                                                mapOf(
                                                    "old" to (result.previous ?: "null"),
                                                    "new" to (result.applied ?: "")
                                                )
                                            )
                                            status = "Global proxy set. Stop will restore the old value."
                                        } else {
                                            globalError = result.error ?: "Global proxy set failed."
                                        }
                                    } finally {
                                        controller.close()
                                        busy = false
                                    }
                                }
                            },
                            enabled = !busy && globalWarning && shizukuReady &&
                                InterceptionBus.running
                        ) { Text("Set global proxy", fontSize = 9.sp) }
                        OutlinedButton(
                            onClick = {
                                globalError = ""
                                busy = true
                                scope.launch {
                                    val controller = ShizukuProxyController(context)
                                    try {
                                        val result = withContext(Dispatchers.IO) {
                                            controller.restore(InterceptionBus.globalProxyPrevious)
                                        }
                                        InterceptionAudit.append(
                                            context,
                                            sessionId,
                                            "global_proxy_restore",
                                            mapOf(
                                                "success" to result.success.toString(),
                                                "previous" to (
                                                    InterceptionBus.globalProxyPrevious ?: "null"
                                                    )
                                            )
                                        )
                                        if (result.success) {
                                            InterceptionBus.globalProxyApplied = false
                                            InterceptionBus.globalProxyPrevious = null
                                            status = "Global proxy restored."
                                        } else {
                                            globalError = result.error ?: "Restore failed."
                                        }
                                    } finally {
                                        controller.close()
                                        busy = false
                                    }
                                }
                            },
                            enabled = !busy && shizukuReady && InterceptionBus.globalProxyApplied
                        ) { Text("Restore now", fontSize = 9.sp) }
                        if (busy) CircularProgressIndicator(Modifier.padding(8.dp))
                    }
                    if (globalError.isNotEmpty()) {
                        Text(globalError, fontSize = 9.sp, color = IntBad)
                    }
                }
            }
        }
        item { Divider(color = IntLine) }
        item {
            Text("Live memory-only proxy log", fontSize = 12.sp, color = IntInfo)
            Text(
                "Bodies are never logged. Sensitive header values are replaced before they " +
                    "enter this list; no export is offered.",
                fontSize = 9.sp,
                color = IntMuted
            )
            Text(
                "Request bodies: not captured. TLS certificate: owned by the upstream proxy.",
                fontSize = 8.sp,
                color = IntMuted
            )
        }
        items(InterceptionBus.log.snapshot().takeLast(200).reversed(), key = { it.id }) { entry ->
            ProxyEntryCard(entry)
        }
        if (InterceptionBus.log.size() == 0) {
            item { Text("No requests seen yet.", fontSize = 9.sp, color = IntMuted) }
        }
        item { Divider(color = IntLine) }
        item {
            Text("Pinning bypass tooling (inert)", fontSize = 12.sp, color = IntWarn)
            Text(PinningGuides.caveat, fontSize = 9.sp, color = IntWarn)
            Row(
                Modifier.padding(top = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = {
                        fridaError = ""
                        scope.launch {
                            try {
                                val generated = withContext(Dispatchers.IO) {
                                    FridaScripts.generate(File(context.filesDir, "interception/frida"))
                                }
                                scripts = generated
                                InterceptionAudit.append(
                                    context,
                                    sessionId,
                                    "frida_generated",
                                    mapOf(
                                        "scripts" to generated.joinToString(";") {
                                            it.name + ":" + it.sha256.take(16)
                                        }
                                    )
                                )
                            } catch (failure: Exception) {
                                fridaError = failure.message ?: failure.javaClass.simpleName
                            }
                        }
                    }
                ) { Text("Generate scripts", fontSize = 9.sp) }
                if (scripts.isNotEmpty()) {
                    OutlinedButton(onClick = { shareScripts(context, scripts) }) {
                        Text("Share scripts", fontSize = 9.sp)
                    }
                }
            }
            if (fridaError.isNotEmpty()) Text(fridaError, fontSize = 9.sp, color = IntBad)
            scripts.forEach { script ->
                Text(
                    "${script.name}  sha256 ${script.sha256.take(16)}...",
                    fontSize = 8.sp,
                    fontFamily = FontFamily.Monospace,
                    color = IntMuted
                )
            }
        }
        item {
            GuideCard("Repackaging guide (user-executed)", PinningGuides.repackaging)
        }
        item {
            GuideCard("Magisk pointer (documentation only)", PinningGuides.magisk)
        }
        item {
            GuideCard("Manual user-CA installation", PinningGuides.manualCa)
        }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = IntCard)) {
                Column(Modifier.padding(10.dp)) {
                    Text("Manual Wi-Fi proxy guide", fontSize = 12.sp, color = IntInfo)
                    PinningGuides.manualProxy.forEachIndexed { index, step ->
                        Text("${index + 1}. $step", fontSize = 9.sp, color = IntMuted)
                    }
                    Text(
                        "No command below is executed by E-Crew. The app cannot prove that a " +
                            "remote interception host is reachable; verify with a test request.",
                        fontSize = 8.sp,
                        color = IntWarn,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun ProxyEntryCard(entry: ProxyLogEntry) {
    Card(colors = CardDefaults.cardColors(containerColor = IntCard)) {
        Column(Modifier.padding(8.dp)) {
            Text(
                "${formatTime(entry.timestamp)}  ${entry.method} ${entry.host}${entry.path}",
                fontSize = 9.sp,
                fontFamily = FontFamily.Monospace,
                color = if (entry.status >= 400) IntBad else IntGood
            )
            Text(
                "status ${entry.status}  up ${entry.bytesUp} B  down ${entry.bytesDown} B" +
                    (entry.note?.let { "  $it" } ?: ""),
                fontSize = 8.sp,
                color = IntMuted
            )
            entry.headers.take(12).forEach { header ->
                Text(
                    "${header.name}: ${header.value}",
                    fontSize = 8.sp,
                    fontFamily = FontFamily.Monospace,
                    color = if (header.sensitive) IntWarn else IntMuted,
                    fontWeight = if (header.sensitive) FontWeight.Bold else FontWeight.Normal
                )
            }
            if (entry.headers.size > 12) {
                Text("${entry.headers.size - 12} more header(s)", fontSize = 8.sp, color = IntMuted)
            }
        }
    }
}

@Composable
private fun GuideCard(title: String, body: String) {
    Card(colors = CardDefaults.cardColors(containerColor = IntCard)) {
        Column(Modifier.padding(10.dp)) {
            Text(title, fontSize = 12.sp, color = IntInfo)
            Text(body, fontSize = 9.sp, color = IntMuted, fontFamily = FontFamily.Monospace)
        }
    }
}

private fun readConsent(context: Context): Long? {
    val store = AuditStore(context)
    return try {
        InterceptionConsent.confirmedAt(store)?.takeIf { it > 0 }
    } finally {
        store.close()
    }
}

private fun readUpstream(context: Context): String {
    val store = AuditStore(context)
    return try {
        UpstreamConfig.load(store)?.display ?: ""
    } finally {
        store.close()
    }
}

private fun shareScripts(context: Context, scripts: List<GeneratedScript>) {
    val uris = ArrayList<Uri>()
    scripts.forEach { script ->
        uris.add(
            FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                script.file
            )
        )
    }
    val intent = Intent(Intent.ACTION_SEND_MULTIPLE).apply {
        type = "text/plain"
        putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(intent, "Share inert Frida scripts"))
}

private fun formatTime(millis: Long): String =
    SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(millis))
