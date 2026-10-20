package com.ecrew.toolkit.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ecrew.toolkit.ai.AiIntake
import com.ecrew.toolkit.capture.CaptureBus
import com.ecrew.toolkit.capture.CaptureEntry
import com.ecrew.toolkit.wifi.ApInfo
import com.ecrew.toolkit.wifi.WifiAlert
import com.ecrew.toolkit.wifi.WifiKit
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
internal fun ApRow(ap: ApInfo) {
    val secColor = when {
        WifiKit.securityRank(ap.security) >= 4 -> AccentGood
        WifiKit.securityRank(ap.security) == 3 -> AccentWarn
        else -> AccentBad
    }
    Card(
        Modifier.fillMaxWidth().padding(vertical = 3.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF182027))
    ) {
        Column(Modifier.padding(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (ap.ssid.isBlank()) "<hidden>" else ap.ssid,
                    fontSize = 13.sp,
                    modifier = Modifier.weight(1f)
                )
                Text("${ap.rssi} dBm", fontSize = 12.sp, color = MonoGray)
            }
            Text(
                ap.bssid,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                color = MonoGray
            )
            Row {
                Text(ap.security, fontSize = 11.sp, color = secColor)
                Text(
                    "   ch ${ap.channel}  ${ap.frequency} MHz",
                    fontSize = 11.sp,
                    color = MonoGray
                )
            }
        }
    }
}

@Composable
fun AlertsTab(alerts: List<WifiAlert>) {
    if (alerts.isEmpty()) {
        Column(
            Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text("No Wi-Fi alerts", color = AccentGood)
            Text(
                "Evil-twin and security-downgrade checks run on every scan.",
                fontSize = 11.sp,
                color = MonoGray
            )
        }
        return
    }
    val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(8.dp)
    ) {
        alerts.forEach { a ->
            val color = when (a.kind) {
                "EVIL_TWIN", "SECURITY_DOWNGRADE" -> AccentBad
                else -> AccentWarn
            }
            Card(
                Modifier.fillMaxWidth().padding(vertical = 3.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF2A1B1D))
            ) {
                Column(Modifier.padding(8.dp)) {
                    Text("${a.kind} · ${fmt.format(Date(a.atMillis))}", color = color, fontSize = 12.sp)
                    Text(a.message, fontSize = 11.sp, color = Color(0xFFCFD8DC))
                }
            }
        }
        Spacer(Modifier.height(8.dp))
    }
}

@Composable
fun WardriveTab(
    wardriving: Boolean,
    fixTime: Long,
    obsCount: Int,
    exportState: String,
    onToggle: () -> Unit,
    onExport: () -> Unit
) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp)
    ) {
        Text("Wardriving", style = MaterialTheme.typography.titleMedium, color = AccentInfo)
        Spacer(Modifier.height(6.dp))
        Text(
            "Correlates every Wi-Fi scan with the current GPS fix and stores it in local SQLite. " +
                "Export produces a WiGLE-style CSV in app storage.",
            fontSize = 12.sp, color = MonoGray
        )
        Spacer(Modifier.height(10.dp))

        fun fmtTime(ms: Long): String =
            if (ms <= 0) "-" else SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(ms))

        KeyValue("Logging", if (wardriving) "ACTIVE (scan every 15 s)" else "stopped",
            if (wardriving) AccentGood else MonoGray)
        KeyValue("Last GPS fix", fmtTime(fixTime))
        KeyValue("Observations", obsCount.toString())
        if (exportState.isNotEmpty()) KeyValue("Last export", exportState, AccentGood)

        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = onToggle) {
                Text(if (wardriving) "Stop logging" else "Start logging")
            }
            OutlinedButton(onClick = onExport, enabled = obsCount > 0) { Text("Export CSV") }
        }
        Spacer(Modifier.height(8.dp))
        Text(
            "Note: Android throttles background scans; keep the screen on for dense collection. " +
                "No root required - monitor-mode capture is out of scope without a supported USB OTG adapter.",
            fontSize = 11.sp, color = AccentWarn
        )
    }
}

// ---------------------------------------------------------- capture tab

@Composable
fun CaptureTab(tick: Int, onToggle: () -> Unit) {
    val context = LocalContext.current
    // `tick` is polled by the host to refresh CaptureBus state.
    val running = CaptureBus.running
    val entries = remember(tick) { CaptureBus.snapshot().asReversed() }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Button(onClick = onToggle, modifier = Modifier.weight(1f)) {
                Text(if (running) "Stop capture" else "Start capture")
            }
            Text(
                if (running) "LIVE" else "idle",
                color = if (running) AccentGood else MonoGray,
                fontSize = 12.sp
            )
        }

        Column(Modifier.padding(horizontal = 8.dp)) {
            KeyValue("Packets", CaptureBus.statsPackets.toString())
            KeyValue("Bytes", CaptureBus.statsBytes.toString())
            if (CaptureBus.pcapPath.isNotEmpty())
                KeyValue("PCAP", CaptureBus.pcapPath.substringAfterLast('/'), AccentGood)
            if (CaptureBus.error.isNotEmpty())
                KeyValue("Error", CaptureBus.error, AccentBad)
            Spacer(Modifier.height(4.dp))
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                TextButton(onClick = {
                    AiIntake.ask(context, "Packet capture", buildString {
                        append("Capture is ")
                        append(if (running) "running" else "idle")
                        append(".\nPackets: ")
                        append(CaptureBus.statsPackets)
                        append("\nBytes: ")
                        append(CaptureBus.statsBytes)
                        if (CaptureBus.pcapPath.isNotEmpty()) {
                            append("\nPCAP file: ")
                            append(CaptureBus.pcapPath.substringAfterLast('/'))
                        }
                        if (CaptureBus.error.isNotEmpty()) {
                            append("\nError: ")
                            append(CaptureBus.error)
                        }
                        val recent = entries.take(20)
                        if (recent.isNotEmpty()) {
                            append("\nRecent metadata (newest first):\n")
                            recent.forEach { entry ->
                                append(entry.display())
                                append('\n')
                            }
                        }
                    })
                }) {
                    Text("Ask Xairex", fontSize = 11.sp)
                }
            }
        }

        Divider(color = Color(0xFF263238))

        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(8.dp)
        ) {
            if (entries.isEmpty()) {
                Text(
                    "Metadata appears here: DNS queries, HTTP URLs, TLS SNI, TCP flows.",
                    fontSize = 11.sp, color = MonoGray
                )
            }
            entries.forEach { e: CaptureEntry ->
                val color = when (e.kind) {
                    "HTTP" -> AccentInfo
                    "TLS" -> AccentWarn
                    "DNS" -> AccentGood
                    "ERROR" -> AccentBad
                    else -> MonoGray
                }
                Text(
                    e.display(),
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = color
                )
            }
            Spacer(Modifier.height(8.dp))
        }
    }
}

