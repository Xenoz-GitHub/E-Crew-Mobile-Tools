package com.ecrew.toolkit.ui.screens

import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.provider.Settings
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ecrew.toolkit.ai.AiIntake
import com.ecrew.toolkit.wifi.ApInfo
import com.ecrew.toolkit.wifi.WifiKit
import com.ecrew.toolkit.wps.SystemWpsEngine
import com.ecrew.toolkit.wps.WpsAuditDb
import com.ecrew.toolkit.wps.WpsPhase
import com.ecrew.toolkit.wps.WpsRateLimiter
import com.ecrew.toolkit.wps.WpsRunController
import com.ecrew.toolkit.wps.WpsText
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** One row of the feasibility matrix that must match the design note verbatim. */
private data class LimitRow(val capability: String, val feasible: Boolean, val basis: String)

private val LIMIT_ROWS = listOf(
    LimitRow(
        "Scan for WPS-enabled networks", true,
        "WifiManager scan results include WPS capability flags"
    ),
    LimitRow(
        "Generate candidate PINs offline", true,
        "Algorithms derive PINs from BSSID; databases of 500+ vendor algorithms (Zhao, Belkin, Arcadyan, etc.) are available"
    ),
    LimitRow(
        "Attempt connection via WPS PIN", true,
        "WifiManager.startWps(WpsInfo, WpsCallback) is available on API 26"
    ),
    LimitRow(
        "Retrieve the WPA/WPA2 password", false,
        "The system does not expose the pre-shared key to non-root apps"
    ),
    LimitRow(
        "Execute Pixie Dust attack", false,
        "Requires low-level chipset control; open-source tools confirm root is required"
    ),
    LimitRow(
        "Customize hotspot SSID/password", false,
        "Only startLocalOnlyHotspot() is available on API 26"
    )
)

@Suppress("DEPRECATION") // WifiManager.startScan is deprecated in API 28; module targets API 26
private fun requestScan(wifi: WifiManager) {
    wifi.startScan()
}

@Suppress("DEPRECATION")
private fun currentAps(wifi: WifiManager): List<ApInfo> =
    try {
        WifiKit.parse(wifi.scanResults)
    } catch (_: SecurityException) {
        emptyList()
    }

/**
 * WPS vulnerability audit tab (Component 10). Rate-limited, foreground-only, and gated by
 * the consent checkbox; see notes/2026-10-19-0945-wps-scanner-design.md for the policy.
 */
@Composable
fun WpsTab(
    limiter: WpsRateLimiter,
    locationGranted: Boolean,
    onRequestLocation: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val wifi = remember(context) {
        context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    }
    val engine = remember(wifi) { wifi?.let { SystemWpsEngine(it) } }
    val audit = remember { WpsAuditDb(context.applicationContext) }

    var aps by remember { mutableStateOf(listOf<ApInfo>()) }
    var status by remember { mutableStateOf("Tap Scan to list WPS-enabled networks.") }
    var scanning by remember { mutableStateOf(false) }
    var limitsOpen by rememberSaveable { mutableStateOf(false) }
    var selected by remember { mutableStateOf<ApInfo?>(null) }
    var consent by remember { mutableStateOf(false) }
    var phase by remember { mutableStateOf<WpsPhase?>(null) }
    var job by remember { mutableStateOf<Job?>(null) }
    var running by remember { mutableStateOf(false) }

    fun scanNow() {
        if (!locationGranted) {
            status = "Location permission is required for Wi-Fi scanning."
            onRequestLocation()
            return
        }
        val wpsWifi = wifi
        if (wpsWifi == null) {
            status = "Wi-Fi service unavailable."
            return
        }
        scope.launch {
            scanning = true
            status = "Scanning..."
            requestScan(wpsWifi)
            delay(1500)
            val found = currentAps(wpsWifi)
                .filter { WifiKit.supportsWps(it.capabilities) }
                .sortedByDescending { it.rssi }
            aps = found
            status = when (found.size) {
                0 -> "No WPS-enabled networks found."
                1 -> "1 WPS-enabled network. Pick it to run a vulnerability test."
                else -> "${found.size} WPS-enabled networks. Pick one to run a vulnerability test."
            }
            scanning = false
        }
    }

    fun start(ap: ApInfo) {
        val wpsEngine = engine
        if (wpsEngine == null) {
            phase = WpsPhase.Stopped("Wi-Fi service unavailable on this device.")
            return
        }
        val controller = WpsRunController(engine = wpsEngine, limiter = limiter, audit = audit)
        running = true
        job = scope.launch {
            try {
                controller.run(ap.ssid, ap.bssid) { update -> phase = update }
            } finally {
                running = false
                job = null
            }
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(8.dp)
    ) {
        Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF33291B))) {
            Text(
                WpsText.BANNER,
                fontSize = 10.sp,
                color = AccentWarn,
                modifier = Modifier.padding(8.dp)
            )
        }
        Spacer(Modifier.height(6.dp))

        TechnicalLimitsCard(limitsOpen) { limitsOpen = !limitsOpen }
        Spacer(Modifier.height(6.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Button(onClick = { scanNow() }, enabled = !scanning && !running) {
                Text(if (scanning) "Scanning..." else "Scan for WPS networks", fontSize = 12.sp)
            }
            Spacer(Modifier.width(8.dp))
            Text(status, fontSize = 10.sp, color = MonoGray, modifier = Modifier.weight(1f))
        }

        aps.forEach { ap ->
            WpsNetworkCard(
                ap = ap,
                selected = selected == ap,
                consent = consent,
                running = running,
                showTestForm = phase == null,
                onToggleSelect = {
                    selected = if (selected == ap) null else ap
                    consent = false
                    phase = null
                },
                onConsentChange = { consent = it },
                onStart = { start(ap) }
            )
        }

        when (val current = phase) {
            null -> Unit
            is WpsPhase.Testing -> TestingCard(current) { job?.cancel() }
            WpsPhase.Success -> SuccessCard { phase = null }
            is WpsPhase.Stopped -> StoppedCard(
                message = current.message,
                contextBody = buildString {
                    selected?.let { ap ->
                        append("Access point: ")
                        append(ap.ssid.ifEmpty { "(hidden)" })
                        append(" (")
                        append(ap.bssid)
                        append(") - ")
                        append(ap.rssi)
                        append(" dBm, ")
                        append(ap.security)
                        append(", WPS-enabled\n")
                    }
                    append("WPS vulnerability test outcome: ")
                    append(current.message)
                },
                onClear = { phase = null }
            )
        }
        Spacer(Modifier.height(12.dp))
    }
}

@Composable
private fun TechnicalLimitsCard(open: Boolean, onToggle: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column {
            Row(
                Modifier
                    .fillMaxWidth()
                    .clickable(onClick = onToggle)
                    .padding(10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "Technical Limits",
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp,
                    modifier = Modifier.weight(1f)
                )
                Text(if (open) "HIDE" else "SHOW", fontSize = 10.sp, color = AccentInfo)
            }
            if (open) {
                LIMIT_ROWS.forEach { row ->
                    Column(Modifier.padding(horizontal = 10.dp, vertical = 3.dp)) {
                        Row {
                            Text(row.capability, fontSize = 11.sp, modifier = Modifier.weight(1f))
                            Text(
                                if (row.feasible) "Yes" else "No",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (row.feasible) AccentGood else AccentBad
                            )
                        }
                        Text(row.basis, fontSize = 9.sp, color = MonoGray)
                    }
                }
                Spacer(Modifier.height(6.dp))
            }
        }
    }
}

@Composable
private fun WpsNetworkCard(
    ap: ApInfo,
    selected: Boolean,
    consent: Boolean,
    running: Boolean,
    showTestForm: Boolean,
    onToggleSelect: () -> Unit,
    onConsentChange: (Boolean) -> Unit,
    onStart: () -> Unit
) {
    Card(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Column(Modifier.padding(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        ap.ssid.ifEmpty { "(hidden)" },
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        "${ap.bssid}   ${ap.rssi} dBm   ch ${ap.channel}",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        color = MonoGray
                    )
                    Text("${ap.security}   WPS-enabled", fontSize = 10.sp, color = AccentInfo)
                }
                TextButton(onClick = onToggleSelect, enabled = !running) {
                    Text(if (selected) "Cancel" else "Test Vulnerability", fontSize = 11.sp)
                }
            }
            if (selected && showTestForm) {
                Spacer(Modifier.height(4.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = consent, onCheckedChange = onConsentChange)
                    Text(WpsText.CONSENT, fontSize = 11.sp)
                }
                Button(onClick = onStart, enabled = consent) {
                    Text("Start Test")
                }
                Text(
                    "Attempts are spaced at least 35 seconds apart; the test stops automatically " +
                        "after 5 consecutive failures.",
                    fontSize = 9.sp,
                    color = MonoGray
                )
            }
        }
    }
}

@Composable
private fun TestingCard(phase: WpsPhase.Testing, onStop: () -> Unit) {
    Card(
        Modifier.fillMaxWidth().padding(top = 6.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF16262E))
    ) {
        Column(Modifier.padding(10.dp)) {
            Text("WPS PIN audit running", fontWeight = FontWeight.Bold, fontSize = 13.sp)
            Spacer(Modifier.height(2.dp))
            Text(phase.pin, fontFamily = FontFamily.Monospace, fontSize = 22.sp)
            Text("Algorithm: ${phase.algorithm}", fontSize = 10.sp, color = MonoGray)
            Text("Attempt ${phase.attempt} of ${phase.total}", fontSize = 12.sp)
            Text(
                if (phase.waiting) {
                    "Next attempt in ${(phase.waitRemainingMs + 999) / 1000} s"
                } else {
                    "Waiting for the router to answer..."
                },
                fontSize = 12.sp,
                color = if (phase.waiting) AccentWarn else AccentInfo
            )
            Spacer(Modifier.height(6.dp))
            LinearProgressIndicator(Modifier.fillMaxWidth().height(3.dp))
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = onStop) { Text("Stop") }
                Spacer(Modifier.width(8.dp))
                Text(
                    "Leaving this tab stops the test after the current attempt.",
                    fontSize = 9.sp,
                    color = MonoGray,
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

@Composable
private fun SuccessCard(onClear: () -> Unit) {
    val context = LocalContext.current
    Card(
        Modifier.fillMaxWidth().padding(top = 6.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF162E1E))
    ) {
        Column(Modifier.padding(10.dp)) {
            Text("Connected via WPS", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = AccentGood)
            Spacer(Modifier.height(2.dp))
            Text(WpsText.SUCCESS, fontSize = 11.sp)
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = {
                    context.startActivity(
                        Intent(Settings.ACTION_WIFI_SETTINGS)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    )
                }) {
                    Text("Open Wi-Fi settings")
                }
                Spacer(Modifier.width(8.dp))
                TextButton(onClick = onClear) { Text("Done") }
            }
        }
    }
}

@Composable
private fun StoppedCard(message: String, contextBody: String, onClear: () -> Unit) {
    val context = LocalContext.current
    Card(
        Modifier.fillMaxWidth().padding(top = 6.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF2E1A16))
    ) {
        Column(Modifier.padding(10.dp)) {
            Text("Test stopped", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = AccentWarn)
            Spacer(Modifier.height(2.dp))
            Text(message, fontSize = 11.sp)
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = onClear) { Text("Clear") }
                Spacer(Modifier.width(8.dp))
                TextButton(
                    onClick = { AiIntake.ask(context, "WPS vulnerability test", contextBody) }
                ) {
                    Text("Ask Xairex", fontSize = 11.sp)
                }
            }
        }
    }
}
