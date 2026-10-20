package com.ecrew.toolkit.ui.screens

import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.content.Context
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.ecrew.toolkit.remote.NsdHelper
import com.ecrew.toolkit.remote.RemoteTarget
import kotlinx.coroutines.delay

/**
 * Discover screen (spec Component 6): mDNS agents on the LAN plus the phone's paired
 * Bluetooth devices, with pull-to-refresh and explicit empty states.
 */
@Composable
fun RemoteDiscoverScreen(onPick: (RemoteTarget) -> Unit) {
    val context = LocalContext.current
    val nsd = remember { NsdHelper(context.applicationContext) }
    var lanServices by remember { mutableStateOf<List<NsdHelper.Discovered>>(emptyList()) }
    var discoveryError by remember { mutableStateOf<String?>(null) }
    var btDevices by remember { mutableStateOf<List<Pair<String, String>>>(emptyList()) }
    var refreshing by remember { mutableStateOf(false) }
    var refreshTick by remember { mutableIntStateOf(0) }
    var pullOffset by remember { mutableFloatStateOf(0f) }

    LaunchedEffect(refreshTick) {
        refreshing = true
        discoveryError = null
        nsd.stop()
        nsd.start(
            onChanged = { services ->
                lanServices = services
                refreshing = false
            },
            onError = { message ->
                discoveryError = message
                refreshing = false
            }
        )
        btDevices = loadBondedDevices(context.applicationContext)
        delay(4_000)
        refreshing = false
    }
    DisposableEffect(Unit) {
        onDispose { nsd.stop() }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .pointerInput(Unit) {
                detectVerticalDragGestures(
                    onDragEnd = {
                        if (pullOffset > PULL_THRESHOLD_PX) refreshTick += 1
                        pullOffset = 0f
                    },
                    onVerticalDrag = { change, dragAmount ->
                        if (dragAmount > 0f) {
                            pullOffset += dragAmount
                            change.consume()
                        }
                    }
                )
            }
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        when {
            refreshing -> Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(modifier = Modifier.size(18.dp))
                Text(
                    text = "Scanning: mDNS (_ecrew-remote._tcp) + paired devices...",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(start = 8.dp)
                )
            }
            pullOffset > PULL_THRESHOLD_PX ->
                Text("Release to refresh", style = MaterialTheme.typography.bodySmall)
            pullOffset > 0f ->
                Text("Pull down to refresh", style = MaterialTheme.typography.bodySmall)
        }

        Text(
            text = "Nearby agents (LAN)",
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(top = 16.dp)
        )
        if (lanServices.isEmpty()) {
            Text(
                text = "No agents found yet. On the device to support, open E-Crew Agent, " +
                    "tap Start listening, and make sure both devices are on the same network.",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 6.dp)
            )
        } else {
            lanServices.forEach { service ->
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp)
                        .clickable { onPick(RemoteTarget.Lan(service.name, service.host, service.port)) }
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(service.name, style = MaterialTheme.typography.titleSmall)
                        Text(
                            text = "${service.host}:${service.port}",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        }
        discoveryError?.let { message ->
            Text(
                text = message,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 6.dp)
            )
        }

        Text(
            text = "Paired Bluetooth devices",
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(top = 24.dp)
        )
        if (btDevices.isEmpty()) {
            Text(
                text = "No paired devices (or Bluetooth is off). Pair the agent device in the " +
                    "system Bluetooth settings first, then pull down to refresh.",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 6.dp)
            )
        } else {
            btDevices.forEach { (name, address) ->
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp)
                        .clickable { onPick(RemoteTarget.Bluetooth(name, address)) }
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(name, style = MaterialTheme.typography.titleSmall)
                        Text(address, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
        Row(modifier = Modifier.padding(top = 16.dp), horizontalArrangement = Arrangement.Start) {
            Text(
                text = "Tip: if mDNS is blocked on this network, pair by IP from the Pair tab.",
                style = MaterialTheme.typography.labelSmall
            )
        }
    }
}

// targetSdk 28 keeps the legacy Bluetooth permission model (install-time BLUETOOTH perms;
// the API 31 runtime pair is not enforced for legacy apps). Failures are caught below.
@SuppressLint("MissingPermission")
private fun loadBondedDevices(context: Context): List<Pair<String, String>> {
    return try {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter = manager?.adapter ?: return emptyList()
        if (!adapter.isEnabled) return emptyList()
        adapter.bondedDevices
            .map { device -> (device.name ?: "Unnamed device") to device.address }
            .sortedBy { it.first }
    } catch (_: Exception) {
        emptyList()
    }
}

private const val PULL_THRESHOLD_PX = 180f
