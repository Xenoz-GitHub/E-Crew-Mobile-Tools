package com.ecrew.toolkit.remote

import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.ImageBitmap
import com.ecrew.protocol.AppInventory

/** A pairable peer chosen on Discover (or typed manually on Pair). */
sealed class RemoteTarget {
    abstract val label: String

    data class Lan(val name: String, val host: String, val port: Int) : RemoteTarget() {
        override val label: String = "$name ($host:$port)"
    }

    data class Bluetooth(val name: String, val address: String) : RemoteTarget() {
        override val label: String = "$name ($address)"
    }
}

enum class RemotePhase { IDLE, CONNECTING, ACTIVE, ENDED }

/**
 * Compose-observable state of the Remote Support controller. Replaced wholesale on every
 * update (`state.value = state.value.copy(...)`) so recomposition stays cheap.
 */
@Immutable
data class RemoteUiState(
    val phase: RemotePhase = RemotePhase.IDLE,
    val sessionId: String? = null,
    val transport: String? = null,
    val peer: String? = null,
    val error: String? = null,
    val streaming: Boolean = false,
    val frames: Long = 0,
    val bytesIn: Long = 0,
    val bytesOut: Long = 0,
    val frame: ImageBitmap? = null,
    val frameWidth: Int = 0,
    val frameHeight: Int = 0,
    val auditLines: List<String> = emptyList(),
    val lastFrameAt: Long = 0L,
    val endReason: String? = null,
    val streamNotice: String? = null,
    val apps: List<AppInventory.Entry> = emptyList(),
    val appsTotal: Int = 0,
    val appsTruncated: Boolean = false,
    val appsLoading: Boolean = false,
    val appsError: String? = null,
    val appsReceivedAt: Long = 0L
)
