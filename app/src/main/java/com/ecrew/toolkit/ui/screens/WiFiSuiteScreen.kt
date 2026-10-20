package com.ecrew.toolkit.ui.screens

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.net.VpnService
import android.net.wifi.WifiManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.ecrew.toolkit.capture.CaptureBus
import com.ecrew.toolkit.service.PacketCaptureService
import com.ecrew.toolkit.wifi.*
import com.ecrew.toolkit.wps.WpsRateLimiter
import kotlinx.coroutines.delay

/**
 * Wi-Fi forensic suite (root-free): passive scan + evil-twin/downgrade
 * detection, wardriving with GPS correlation and CSV export, packet capture
 * and LAN reconnaissance tabs.
 */
@Composable
fun WiFiSuiteScreen() {
    val context = LocalContext.current
    var tab by rememberSaveable { mutableStateOf(0) }

    val wifiManager = remember {
        context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    }
    val gps = remember { GpsLogger(context) }
    val db = remember { WardriveDb(context) }
    // WPS session pacing lives here (not in the tab) so switching tabs inside the suite
    // does not reset the lockout backoff; the tab's leave-cancels rule still applies.
    val wpsLimiter = remember { WpsRateLimiter() }
    val ssidHistory = remember { HashMap<String, String>() }
    val bssidHistory = remember { HashMap<String, String>() }

    var aps by remember { mutableStateOf(listOf<ApInfo>()) }
    var alerts by remember { mutableStateOf(listOf<WifiAlert>()) }
    var lastMsg by remember { mutableStateOf("tap Scan to begin") }
    var locationGranted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
                PackageManager.PERMISSION_GRANTED
        )
    }
    var wardriving by remember { mutableStateOf(false) }
    var fixTime by remember { mutableLongStateOf(0L) }
    var obsCount by remember { mutableIntStateOf(0) }
    var exportState by remember { mutableStateOf("") }
    var tick by remember { mutableIntStateOf(0) }

    val vpnLauncher =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
            if (res.resultCode == Activity.RESULT_OK) PacketCaptureService.start(context)
        }

    fun toggleCapture() {
        if (CaptureBus.running) {
            PacketCaptureService.stop(context)
        } else {
            val prepare = VpnService.prepare(context)
            if (prepare != null) vpnLauncher.launch(prepare)
            else PacketCaptureService.start(context)
        }
    }

    val permLauncher =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            locationGranted = granted
            if (!granted) lastMsg = "location permission denied - scan results will be empty"
        }

    fun performScan() {
        if (!locationGranted) {
            permLauncher.launch(Manifest.permission.ACCESS_FINE_LOCATION)
            return
        }
        @Suppress("DEPRECATION")
        wifiManager.startScan()
        val results = try { wifiManager.scanResults } catch (e: SecurityException) { emptyList() }
        val parsed = WifiKit.parse(results)
        aps = parsed
        alerts = (WifiKit.analyze(parsed, ssidHistory, bssidHistory) + alerts)
            .distinctBy { it.kind + it.message }
            .take(60)
        lastMsg = "${parsed.size} APs, ${alerts.size} alerts"
        if (wardriving) obsCount += db.logScan(parsed, gps.last)
    }

    fun toggleWardrive() {
        if (wardriving) {
            gps.stop()
            wardriving = false
        } else {
            if (!locationGranted) {
                permLauncher.launch(Manifest.permission.ACCESS_FINE_LOCATION)
                return
            }
            if (!gps.start(context)) {
                lastMsg = "GPS start failed - enable location services"
                return
            }
            gps.onFix = { loc -> fixTime = loc.time }
            wardriving = true
            performScan()
        }
    }

    fun exportCsv() {
        val f = db.exportCsv(context)
        exportState = f?.absolutePath ?: "export failed"
        if (f != null) obsCount = db.count()
    }

    LaunchedEffect(wardriving) {
        while (wardriving) {
            delay(15_000)
            performScan()
        }
    }

    // Poll capture state only while the Capture tab is visible.
    LaunchedEffect(tab) {
        if (tab == 3) {
            while (true) {
                delay(700)
                tick++
            }
        }
    }

    DisposableEffect(Unit) {
        onDispose { gps.stop() }
    }

    Column(Modifier.fillMaxSize()) {
        val tabs = listOf("Scan", "Alerts", "Wardrive", "Capture", "LAN", "WPS", "Intercept")
        ScrollableTabRow(selectedTabIndex = tab, containerColor = Color(0xFF141A20)) {
            tabs.forEachIndexed { i, name ->
                Tab(
                    selected = tab == i,
                    onClick = { tab = i },
                    text = { Text(name, fontSize = 12.sp) }
                )
            }
        }
        when (tab) {
            0 -> ScanTab(aps, lastMsg, locationGranted) { performScan() }
            1 -> AlertsTab(alerts)
            2 -> WardriveTab(
                wardriving = wardriving,
                fixTime = fixTime,
                obsCount = obsCount,
                exportState = exportState,
                onToggle = { toggleWardrive() },
                onExport = { exportCsv() }
            )
            3 -> CaptureTab(tick) { toggleCapture() }
            4 -> LanTab()
            5 -> WpsTab(
                limiter = wpsLimiter,
                locationGranted = locationGranted,
                onRequestLocation = { permLauncher.launch(Manifest.permission.ACCESS_FINE_LOCATION) }
            )
            else -> InterceptionTab()
        }
    }
}

    // --------------------------------------------------------------- scan tab

    @Composable
    private fun ScanTab(
        aps: List<ApInfo>,
        lastMsg: String,
        locationGranted: Boolean,
        onScan: () -> Unit
    ) {
        Column(Modifier.fillMaxSize()) {
            Row(
                Modifier.fillMaxWidth().padding(8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Button(onClick = onScan, modifier = Modifier.weight(1f)) { Text("Scan now") }
                Text(lastMsg, fontSize = 11.sp, color = MonoGray)
            }
            if (!locationGranted) {
                Text(
                    "  Location permission is required by Android to read Wi-Fi scan results.",
                    fontSize = 11.sp,
                    color = AccentWarn,
                    modifier = Modifier.padding(bottom = 4.dp)
                )
            }
            Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState())
                    .padding(horizontal = 8.dp)
            ) {
                if (aps.isEmpty()) {
                    Text(
                        "No access points yet - press Scan now.",
                        color = MonoGray,
                        fontSize = 12.sp
                    )
                }
                aps.sortedByDescending { it.rssi }.forEach { ApRow(it) }
                Spacer(Modifier.height(8.dp))
            }
        }
    }

