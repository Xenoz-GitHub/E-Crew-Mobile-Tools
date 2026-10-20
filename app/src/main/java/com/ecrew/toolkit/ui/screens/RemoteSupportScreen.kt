package com.ecrew.toolkit.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.ecrew.toolkit.remote.RemotePhase
import com.ecrew.toolkit.remote.RemoteSessionController
import com.ecrew.toolkit.remote.RemoteTarget

/** Tabs of the Remote Support feature (spec Component 6). */
enum class RemoteTab(val title: String) {
    SEND("Send Agent"),
    DISCOVER("Discover"),
    PAIR("Pair"),
    AUDIT("Audit")
}

/**
 * Entry point of the Remote Support feature: hosts the session controller for the lifetime
 * of the screen and switches between the tabbed workflow and the full-screen session view.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RemoteSupportScreen() {
    val context = LocalContext.current
    val controller = remember { RemoteSessionController(context.applicationContext) }
    DisposableEffect(Unit) {
        onDispose { controller.dispose() }
    }

    var tab by remember { mutableStateOf(RemoteTab.DISCOVER) }
    var pendingTarget by remember { mutableStateOf<RemoteTarget?>(null) }

    val state = controller.state.value
    Scaffold(topBar = { TopAppBar(title = { Text("Remote Support") }) }) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state.phase) {
                RemotePhase.CONNECTING -> ConnectingPane(state.peer, onCancel = { controller.cancelConnect() })
                RemotePhase.ACTIVE, RemotePhase.ENDED -> RemoteSessionViewScreen(
                    controller = controller,
                    onDone = {
                        controller.reset()
                        tab = RemoteTab.DISCOVER
                    }
                )
                RemotePhase.IDLE -> {
                    TabRow(selectedTabIndex = tab.ordinal) {
                        RemoteTab.values().forEach { candidate ->
                            Tab(
                                selected = tab == candidate,
                                onClick = { tab = candidate },
                                text = { Text(candidate.title) }
                            )
                        }
                    }
                    when (tab) {
                        RemoteTab.SEND -> RemoteSendScreen()
                        RemoteTab.DISCOVER -> RemoteDiscoverScreen(
                            onPick = { target ->
                                pendingTarget = target
                                tab = RemoteTab.PAIR
                            }
                        )
                        RemoteTab.PAIR -> RemotePairScreen(
                            controller = controller,
                            pendingTarget = pendingTarget,
                            onClearTarget = { pendingTarget = null }
                        )
                        RemoteTab.AUDIT -> RemoteAuditScreen()
                    }
                }
            }
        }
    }
}

@Composable
private fun ConnectingPane(peer: String?, onCancel: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        CircularProgressIndicator()
        Text(
            text = "Connecting to ${peer ?: "agent"}...",
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(top = 16.dp)
        )
        Text(
            text = "Handshake and AES-256-GCM session setup",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 4.dp)
        )
        Row(modifier = Modifier.padding(top = 24.dp)) {
            Button(onClick = onCancel) { Text("Cancel") }
        }
    }
}
