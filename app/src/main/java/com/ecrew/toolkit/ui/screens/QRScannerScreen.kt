package com.ecrew.toolkit.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.SportsEsports
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.ecrew.toolkit.util.PayloadParser
import com.ecrew.toolkit.util.ParsedPayload
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanIntentResult
import com.journeyapps.barcodescanner.ScanOptions

internal val AccentGood = Color(0xFF66BB6A)
internal val AccentWarn = Color(0xFFFFB300)
internal val AccentBad = Color(0xFFEF5350)
internal val AccentInfo = Color(0xFF4FC3F7)
internal val MonoGray = Color(0xFFB0BEC5)

@Composable
fun QRScannerScreen(onOpenGames: () -> Unit = {}) {
    val context = LocalContext.current
    var parsed by remember { mutableStateOf<ParsedPayload?>(null) }
    var manualText by rememberSaveable { mutableStateOf("") }
    var tab by rememberSaveable { mutableStateOf(0) }

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result: ScanIntentResult ->
        val contents = result.contents
        if (!contents.isNullOrEmpty()) parsed = PayloadParser.parse(contents)
    }

    val permLauncher =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) scanLauncher.launch(scanOptions())
        }

    fun startScan() {
        val granted = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        if (granted) scanLauncher.launch(scanOptions()) else permLauncher.launch(Manifest.permission.CAMERA)
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(onClick = { startScan() }, modifier = Modifier.weight(1f)) {
                Text("Scan QR")
            }
            OutlinedButton(
                onClick = { parsed = PayloadParser.parse(manualText) },
                enabled = manualText.isNotBlank(),
                modifier = Modifier.weight(1f)
            ) {
                Text("Analyze Input")
            }
        }
        Button(
            onClick = onOpenGames,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp).height(54.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = Color(0xFF10283A),
                contentColor = AccentInfo
            ),
            border = BorderStroke(1.dp, AccentInfo.copy(alpha = 0.65f))
        ) {
            Icon(Icons.Default.SportsEsports, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Column(Modifier.weight(1f)) {
                Text("Games Hub", fontSize = 13.sp, fontWeight = FontWeight.Bold)
                Text("GridBlocks and more games", fontSize = 9.sp, color = MonoGray)
            }
            Icon(Icons.Default.ChevronRight, contentDescription = null)
        }
        OutlinedTextField(
            value = manualText,
            onValueChange = { manualText = it },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
            label = { Text("Paste payload for offline analysis") },
            minLines = 2,
            maxLines = 4
        )

        val p = parsed
        if (p == null) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    "Scan a QR code or paste a payload.\nAll processing stays on this device.",
                    color = MonoGray
                )
            }
        } else {
            val tabs = listOf("Overview", "Layers", "Hex", "CBOR", "IOCs", "Threats")
            ScrollableTabRow(selectedTabIndex = tab, containerColor = Color(0xFF141A20)) {
                tabs.forEachIndexed { i, name ->
                    Tab(
                        selected = tab == i,
                        onClick = { tab = i },
                        text = { Text(name, fontSize = 12.sp) }
                    )
                }
            }
            Column(
                Modifier.verticalScroll(rememberScrollState()).padding(8.dp)
            ) {
                when (tab) {
                    0 -> QrOverviewTab(p)
                    1 -> QrLayersTab(p)
                    2 -> QrHexTab(p)
                    3 -> QrCborTab(p)
                    4 -> QrIndicatorsTab(p)
                    5 -> QrThreatsTab(p)
                }
            }
        }
    }
}

private fun scanOptions(): ScanOptions =
    ScanOptions()
        .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
        .setPrompt("Align the QR code for offline forensic capture")
        .setBeepEnabled(true)
        .setOrientationLocked(true)
        .setTimeout(0)

