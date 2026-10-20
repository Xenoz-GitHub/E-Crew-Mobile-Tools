package com.ecrew.toolkit.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ecrew.toolkit.lan.LanScanner
import com.ecrew.toolkit.lan.MdnsSsdpDiscoverer
import com.ecrew.toolkit.lan.OuiLookup
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * LAN reconnaissance tab (Phase 6): ARP table read + OUI vendor resolution,
 * TCP sweep with port/banner scan, and mDNS/SSDP service discovery. All
 * checks are passive/root-free and stay on the local network.
 */
@Composable
internal fun LanTab() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val discoverer = remember { MdnsSsdpDiscoverer(context) }

    var subnet by remember { mutableStateOf("") }
    var ouiEntries by remember { mutableIntStateOf(0) }
    var hosts by remember { mutableStateOf(listOf<LanScanner.Host>()) }
    var services by remember {
        mutableStateOf(emptyList<MdnsSsdpDiscoverer.DiscoveredService>())
    }
    var status by remember { mutableStateOf("idle") }
    var busy by remember { mutableStateOf(false) }
    var discovering by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        val info = withContext(Dispatchers.IO) {
            OuiLookup.init(context)
            LanScanner.getLocalNetwork(context) to OuiLookup.entryCount()
        }
        subnet = info.first ?: "192.168.1.0/24"
        ouiEntries = info.second
    }

    DisposableEffect(Unit) {
        onDispose { discoverer.stopMdnsDiscovery() }
    }

    fun launchScan(label: String, block: suspend () -> String) {
        if (busy) return
        busy = true
        status = label
        scope.launch {
            status = try {
                withContext(Dispatchers.IO) { block() }
            } catch (e: Exception) {
                "failed: ${e.message ?: e.javaClass.simpleName}"
            }
            busy = false
        }
    }

    Column(Modifier.fillMaxSize()) {
        Column(Modifier.padding(8.dp)) {
            Text(
                "LAN reconnaissance",
                style = MaterialTheme.typography.titleMedium,
                color = AccentInfo
            )
            Spacer(Modifier.height(4.dp))
            KeyValue("Subnet", if (subnet.isEmpty()) "detecting..." else subnet)
            KeyValue("OUI database", "$ouiEntries prefixes")
            KeyValue("Status", status, if (busy) AccentWarn else MonoGray)
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = {
                        launchScan("reading /proc/net/arp...") {
                            val found = LanScanner.readArpTable()
                            hosts = found
                            "${found.size} ARP entries"
                        }
                    },
                    enabled = !busy
                ) { Text("ARP table") }
                OutlinedButton(
                    onClick = {
                        launchScan("sweeping $subnet (up to 30 s)...") {
                            val result = LanScanner.scanNetwork(context, subnet)
                            hosts = result.hosts
                            "sweep: ${result.hosts.size} hosts in ${result.scanTime} ms"
                        }
                    },
                    enabled = !busy
                ) { Text("Sweep + ports") }
            }
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = {
                        if (!busy) {
                            busy = true
                            discovering = true
                            status = "mDNS discovery (10 s window)..."
                            scope.launch {
                                withContext(Dispatchers.IO) { discoverer.startMdnsDiscovery() }
                                delay(11_000)
                                val mdns = discoverer.getDiscoveredServices()
                                status = "SSDP discovery (5 s)..."
                                val ssdp = withContext(Dispatchers.IO) {
                                    discoverer.discoverSsdp(5000)
                                }
                                services = (mdns + ssdp)
                                    .distinctBy { it.protocol + it.address + it.port + it.name }
                                status = "${mdns.size} mDNS + ${ssdp.size} SSDP services"
                                discovering = false
                                busy = false
                            }
                        }
                    },
                    enabled = !busy
                ) { Text(if (discovering) "Discovering..." else "mDNS / SSDP") }
                OutlinedButton(
                    onClick = { services = discoverer.getDiscoveredServices() },
                    enabled = !busy
                ) { Text("Refresh list") }
            }
        }

        Divider(color = Color(0xFF263238))

        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(8.dp)
        ) {
            if (hosts.isEmpty() && services.isEmpty()) {
                Text(
                    "No results yet. ARP reads the kernel ARP cache; the sweep probes " +
                        "every address of the subnet and scans the 21 most common TCP ports " +
                        "on live hosts; the discovery pass listens for mDNS/SSDP announcements.",
                    fontSize = 11.sp,
                    color = MonoGray
                )
            }
            hosts.forEach { host -> HostCard(host) }
            if (services.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                Text("Discovered services", fontSize = 12.sp, color = AccentInfo)
                services.forEach { svc -> ServiceRow(svc) }
            }
            Spacer(Modifier.height(8.dp))
        }
    }
}

@Composable
private fun HostCard(host: LanScanner.Host) {
    Card(
        Modifier.fillMaxWidth().padding(vertical = 3.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF182027))
    ) {
        Column(Modifier.padding(8.dp)) {
            Row {
                Text(host.ip, fontSize = 13.sp, fontFamily = FontFamily.Monospace)
                if (host.openPorts.isNotEmpty()) {
                    Text(
                        "   ${host.openPorts.size} open port(s)",
                        fontSize = 11.sp,
                        color = AccentGood
                    )
                }
            }
            if (host.mac != null) {
                Text(
                    "${host.mac}${if (host.vendor != null) "  ${host.vendor}" else ""}",
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = if (host.vendor != null) AccentInfo else MonoGray
                )
            }
            host.openPorts.forEach { p ->
                val banner = if (p.banner != null && p.banner != "No banner") "  ${p.banner}" else ""
                Text(
                    "  ${p.port}/${p.service}$banner",
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MonoGray
                )
            }
        }
    }
}

@Composable
private fun ServiceRow(svc: MdnsSsdpDiscoverer.DiscoveredService) {
    Column(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(
            "${svc.protocol}  ${svc.name}",
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
            color = AccentGood
        )
        Text(
            "${svc.type}  ${svc.address}:${svc.port}",
            fontSize = 10.sp,
            fontFamily = FontFamily.Monospace,
            color = MonoGray
        )
    }
}
