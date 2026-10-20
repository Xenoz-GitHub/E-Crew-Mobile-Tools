package com.ecrew.toolkit.messaging

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

/**
 * Process-wide messaging state shared between the foreground service (writer) and the
 * Compose UI (reader). Same-process singleton - no IPC. Compose snapshot state, matching
 * the RemoteSessionController pattern; the service writes from IO threads, the UI reads
 * during composition.
 */
object MessagingBus {

    /** Peers currently reachable (LAN beacon/NSD + handshaken Bluetooth). */
    var nearby: List<NearbyPeer> by mutableStateOf(emptyList())

    /** Bluetooth devices found by the last scan (screen-triggered). */
    var btDiscovered: List<BtDeviceInfo> by mutableStateOf(emptyList())

    /** True while a classic Bluetooth discovery run is active. */
    var btScanning: Boolean by mutableStateOf(false)

    /** Address currently being probed/paired, for per-row progress UI. */
    var btBusyAddress: String? by mutableStateOf(null)

    /** Last human-readable status line (probe result, discoverable window, errors). */
    var statusText: String? by mutableStateOf(null)

    /** Mirrors MessagingPrefs.visible for the toggle UI. */
    var visible: Boolean by mutableStateOf(false)

    /** True while the Chat screen is composed (notification suppression + listen lifetime). */
    var screenActive: Boolean by mutableStateOf(false)

    /** Bumped on every DB write so open screens reload. */
    var revision: Long by mutableLongStateOf(0L)

    /** Set by a notification tap; MainScreen navigates to Chat and clears it. */
    var openChatRequested: Boolean by mutableStateOf(false)

    fun bump() {
        revision += 1
    }

    fun setStatus(text: String?) {
        statusText = text
    }
}
