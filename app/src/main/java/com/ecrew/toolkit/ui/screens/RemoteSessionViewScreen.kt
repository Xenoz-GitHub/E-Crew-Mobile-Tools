package com.ecrew.toolkit.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CropSquare
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Keyboard
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.ReceiptLong
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.ecrew.protocol.AppInventory
import com.ecrew.protocol.GlobalActions
import com.ecrew.toolkit.remote.RemotePhase
import com.ecrew.toolkit.remote.RemoteSessionController
import com.ecrew.toolkit.remote.RemoteUiState
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Session View (spec Component 6): letterboxed live frames with normalized-coordinate
 * input (tap + swipe), a translucent vector-icon toolbar (stream toggle, back/home/recents/
 * notifications, keyboard, audit overlay, end session), and live session telemetry.
 */
@Composable
fun RemoteSessionViewScreen(controller: RemoteSessionController, onDone: () -> Unit) {
    val state = controller.state.value
    var showKeyboard by remember { mutableStateOf(false) }
    var showAudit by remember { mutableStateOf(false) }
    var showApps by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize()) {
        SessionHeader(state)
        Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
            FrameSurface(controller, state)
            if (state.phase == RemotePhase.ACTIVE) {
                SessionToolbar(
                    controller = controller,
                    state = state,
                    onKeyboard = { showKeyboard = true },
                    onApps = {
                        showApps = true
                        if (!state.appsLoading && state.apps.isEmpty()) {
                            controller.requestAppInventory()
                        }
                    },
                    onAudit = { showAudit = true },
                    modifier = Modifier.align(Alignment.TopCenter).padding(top = 8.dp)
                )
            }
            if (showAudit) {
                AuditOverlay(
                    lines = state.auditLines,
                    onClose = { showAudit = false },
                    modifier = Modifier.align(Alignment.BottomCenter)
                )
            }
            if (state.phase == RemotePhase.ENDED) {
                EndedCard(
                    reason = state.endReason,
                    onDone = onDone,
                    modifier = Modifier.align(Alignment.Center)
                )
            }
        }
    }

    if (showKeyboard) {
        KeyboardDialog(
            onSend = { text ->
                controller.sendText(text)
                showKeyboard = false
            },
            onDismiss = { showKeyboard = false }
        )
    }

    if (showApps) {
        AppInventoryOverlay(
            state = state,
            onRequest = { controller.requestAppInventory() },
            onClose = { showApps = false }
        )
    }
}

@Composable
private fun SessionHeader(state: RemoteUiState) {
    Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)) {
        Text(
            text = "Session ${state.sessionId?.take(8) ?: "..."} / ${state.transport ?: "?"} / " +
                "${state.peer ?: "?"}",
            style = MaterialTheme.typography.titleSmall
        )
        Text(
            text = "${state.frames} frames | in ${state.bytesIn / 1024} KB | " +
                "out ${state.bytesOut / 1024} KB | " +
                if (state.streaming) "streaming" else "not streaming",
            style = MaterialTheme.typography.bodySmall
        )
        state.streamNotice?.let { notice ->
            Text(
                text = notice,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}

@Composable
private fun FrameSurface(controller: RemoteSessionController, state: RemoteUiState) {
    val frame = state.frame
    if (frame == null) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("Waiting for screen frames", style = MaterialTheme.typography.titleMedium)
                Text(
                    text = "The device owner must accept the system capture dialog. " +
                        "Frames start right after that.",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 6.dp, start = 24.dp, end = 24.dp)
                )
                Row(modifier = Modifier.padding(top = 16.dp)) {
                    Button(
                        onClick = { controller.requestStreaming(true) },
                        enabled = state.phase == RemotePhase.ACTIVE
                    ) { Text("Request streaming") }
                }
            }
        }
        return
    }

    BoxWithConstraints(
        modifier = Modifier.fillMaxSize().background(Color.Black)
    ) {
        val viewWidth = constraints.maxWidth.toFloat()
        val viewHeight = constraints.maxHeight.toFloat()
        val frameWidth = (state.frameWidth.takeIf { it > 0 } ?: frame.width).toFloat()
        val frameHeight = (state.frameHeight.takeIf { it > 0 } ?: frame.height).toFloat()
        val scale = minOf(viewWidth / frameWidth, viewHeight / frameHeight)
        val drawWidth = frameWidth * scale
        val drawHeight = frameHeight * scale
        val offsetX = (viewWidth - drawWidth) / 2f
        val offsetY = (viewHeight - drawHeight) / 2f

        fun toNormalized(position: Offset): Pair<Double, Double>? {
            val nx = ((position.x - offsetX) / drawWidth).toDouble()
            val ny = ((position.y - offsetY) / drawHeight).toDouble()
            if (nx < 0.0 || ny < 0.0 || nx > 1.0 || ny > 1.0) return null
            return nx to ny
        }

        Image(
            bitmap = frame,
            contentDescription = null,
            contentScale = ContentScale.Fit,
            modifier = Modifier.fillMaxSize()
        )
        Box(
            modifier = Modifier
                .fillMaxSize()
                .pointerInput(offsetX, offsetY, drawWidth, drawHeight) {
                    detectTapGestures { position ->
                        toNormalized(position)?.let { (nx, ny) -> controller.sendTap(nx, ny) }
                    }
                }
                .pointerInput(offsetX, offsetY, drawWidth, drawHeight) {
                    var start: Offset? = null
                    var startAt = 0L
                    var last: Offset? = null
                    detectDragGestures(
                        onDragStart = { position ->
                            start = position
                            startAt = System.currentTimeMillis()
                            last = position
                        },
                        onDrag = { change, _ ->
                            last = change.position
                            change.consume()
                        },
                        onDragEnd = {
                            val from = start
                            val to = last
                            if (from != null && to != null) {
                                val a = toNormalized(from)
                                val b = toNormalized(to)
                                if (a != null && b != null) {
                                    val duration = (System.currentTimeMillis() - startAt)
                                        .coerceIn(100L, 1_500L)
                                    controller.sendSwipe(a.first, a.second, b.first, b.second, duration)
                                }
                            }
                            start = null
                            last = null
                        },
                        onDragCancel = {
                            start = null
                            last = null
                        }
                    )
                }
        )
    }
}

@Composable
private fun SessionToolbar(
    controller: RemoteSessionController,
    state: RemoteUiState,
    onKeyboard: () -> Unit,
    onApps: () -> Unit,
    onAudit: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier,
        color = Color.Black.copy(alpha = 0.55f),
        shape = RoundedCornerShape(24.dp)
    ) {
        Row(
            modifier = Modifier
                .horizontalScroll(rememberScrollState())
                .padding(horizontal = 2.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = { controller.requestStreaming(!state.streaming) }) {
                Icon(
                    imageVector = if (state.streaming) Icons.Default.Pause else Icons.Default.PlayArrow,
                    contentDescription = "Start or pause streaming",
                    tint = Color.White
                )
            }
            IconButton(onClick = { controller.sendGlobalAction(GlobalActions.BACK) }) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color.White)
            }
            IconButton(onClick = { controller.sendGlobalAction(GlobalActions.HOME) }) {
                Icon(Icons.Default.Home, contentDescription = "Home", tint = Color.White)
            }
            IconButton(onClick = { controller.sendGlobalAction(GlobalActions.RECENTS) }) {
                Icon(Icons.Default.CropSquare, contentDescription = "Recents", tint = Color.White)
            }
            IconButton(onClick = { controller.sendGlobalAction(GlobalActions.NOTIFICATIONS) }) {
                Icon(Icons.Default.Notifications, contentDescription = "Notifications", tint = Color.White)
            }
            IconButton(onClick = onKeyboard) {
                Icon(Icons.Default.Keyboard, contentDescription = "Keyboard", tint = Color.White)
            }
            IconButton(onClick = onApps) {
                Icon(Icons.Default.Apps, contentDescription = "Remote app inventory", tint = Color.White)
            }
            IconButton(onClick = onAudit) {
                Icon(Icons.Default.ReceiptLong, contentDescription = "Audit overlay", tint = Color.White)
            }
            IconButton(onClick = { controller.endSession() }) {
                Icon(
                    Icons.Default.PowerSettingsNew,
                    contentDescription = "End session",
                    tint = Color(0xFFFF6B6B)
                )
            }
        }
    }
}

@Composable
private fun AuditOverlay(lines: List<String>, onClose: () -> Unit, modifier: Modifier = Modifier) {
    Surface(
        modifier = modifier.padding(8.dp),
        color = Color.Black.copy(alpha = 0.78f),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "In-session audit (live)",
                    color = Color.White,
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f)
                )
                TextButton(onClick = onClose) { Text("Close") }
            }
            Column(
                modifier = Modifier
                    .height(180.dp)
                    .width(300.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                lines.takeLast(40).reversed().forEach { line ->
                    Text(
                        text = line,
                        color = Color.White.copy(alpha = 0.9f),
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }
        }
    }
}

/**
 * Read-only inventory of the agent's installed packages. Requested explicitly from the
 * toolbar; search and the user/system filter are local (the full capped list stays in the
 * controller's memory only). Copy writes a plain-text snapshot to the clipboard.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppInventoryOverlay(
    state: RemoteUiState,
    onRequest: () -> Unit,
    onClose: () -> Unit
) {
    val clipboard = LocalClipboardManager.current
    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf(AppFilter.ALL) }
    var copied by remember { mutableStateOf(false) }
    val clockFormat = remember { SimpleDateFormat("HH:mm:ss", Locale.US) }
    val stampFormat = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US) }

    val userCount = state.apps.count { !it.system }
    val systemCount = state.apps.size - userCount
    val received = remember(state.appsReceivedAt) {
        if (state.appsReceivedAt > 0) clockFormat.format(Date(state.appsReceivedAt)) else null
    }
    val visible = remember(state.apps, query, filter) {
        val needle = query.trim()
        state.apps.filter { entry ->
            val matchesFilter = when (filter) {
                AppFilter.ALL -> true
                AppFilter.USER -> !entry.system
                AppFilter.SYSTEM -> entry.system
            }
            matchesFilter && (
                needle.isEmpty() ||
                    entry.label.contains(needle, ignoreCase = true) ||
                    entry.packageName.contains(needle, ignoreCase = true) ||
                    entry.version?.contains(needle, ignoreCase = true) == true
                )
        }
    }
    val canRequest = state.phase == RemotePhase.ACTIVE && !state.appsLoading

    fun copyAll() {
        if (state.apps.isEmpty()) return
        val header = buildString {
            appendLine("E-Crew remote app inventory")
            appendLine("Peer: ${state.peer ?: "unknown"}")
            appendLine("Session: ${state.sessionId?.take(8) ?: "unknown"}")
            val at = state.appsReceivedAt.takeIf { it > 0 } ?: System.currentTimeMillis()
            appendLine("Received: ${stampFormat.format(Date(at))}")
            if (state.appsTruncated) {
                appendLine("Capped: ${state.apps.size} of ${state.appsTotal} installed packages")
            }
            appendLine("Name | Package | Version | Type")
        }
        val rows = state.apps.joinToString("\n") { entry ->
            "${entry.label} | ${entry.packageName} | ${entry.version ?: "-"} | " +
                if (entry.system) "system" else "user"
        }
        clipboard.setText(AnnotatedString(header + rows))
        copied = true
    }

    Dialog(
        onDismissRequest = onClose,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier.fillMaxWidth(0.95f).fillMaxHeight(0.88f),
            shape = RoundedCornerShape(16.dp),
            tonalElevation = 6.dp
        ) {
            Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "Apps on the remote device",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(onClick = onClose) {
                        Icon(Icons.Default.Close, contentDescription = "Close app inventory")
                    }
                }
                Text(
                    text = if (state.apps.isEmpty()) {
                        "Explicitly request the agent's installed packages; nothing is sent automatically."
                    } else {
                        "$userCount user - $systemCount system" +
                            (received?.let { " - received $it" } ?: "")
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (state.appsTruncated) {
                    Text(
                        text = "Capped at ${AppInventory.MAX_ENTRIES} packages; the device reports " +
                            "${state.appsTotal} installed.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
                if (state.appsLoading) {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth().padding(top = 8.dp))
                }
                if (state.apps.isNotEmpty()) {
                    OutlinedTextField(
                        value = query,
                        onValueChange = {
                            query = it
                            copied = false
                        },
                        label = { Text("Search name, package, or version") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        AppFilter.values().forEach { option ->
                            FilterChip(
                                selected = filter == option,
                                onClick = {
                                    filter = option
                                    copied = false
                                },
                                label = { Text("${option.title} ${option.count(state.apps)}") }
                            )
                        }
                    }
                }
                Box(modifier = Modifier.weight(1f).fillMaxWidth().padding(top = 8.dp)) {
                    when {
                        state.apps.isEmpty() && state.appsLoading -> Column(
                            modifier = Modifier.fillMaxSize(),
                            verticalArrangement = Arrangement.Center,
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            CircularProgressIndicator()
                            Text(
                                text = "Waiting for the agent to return its app list...",
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.padding(top = 12.dp)
                            )
                        }
                        state.apps.isEmpty() -> Column(
                            modifier = Modifier.fillMaxSize(),
                            verticalArrangement = Arrangement.Center,
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                text = state.appsError ?: "No inventory received yet.",
                                color = if (state.appsError != null) {
                                    MaterialTheme.colorScheme.error
                                } else {
                                    MaterialTheme.colorScheme.onSurfaceVariant
                                },
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Button(
                                onClick = {
                                    copied = false
                                    onRequest()
                                },
                                enabled = canRequest,
                                modifier = Modifier.padding(top = 12.dp)
                            ) { Text("Request inventory") }
                        }
                        visible.isEmpty() -> Column(
                            modifier = Modifier.fillMaxSize(),
                            verticalArrangement = Arrangement.Center,
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                text = "No apps match the current filter.",
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                        else -> LazyColumn(modifier = Modifier.fillMaxSize()) {
                            items(visible, key = { it.packageName }) { entry ->
                                AppRow(entry)
                            }
                        }
                    }
                }
                val footerNote = when {
                    state.appsError != null && state.apps.isNotEmpty() -> state.appsError
                    copied -> "Copied ${state.apps.size} apps to the clipboard."
                    state.apps.isEmpty() -> "No entries"
                    else -> "${visible.size} shown of ${state.apps.size}"
                }
                Text(
                    text = footerNote,
                    style = MaterialTheme.typography.labelSmall,
                    color = if (state.appsError != null) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    modifier = Modifier.padding(top = 4.dp)
                )
                Row(
                    modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    TextButton(
                        onClick = {
                            copied = false
                            onRequest()
                        },
                        enabled = canRequest
                    ) { Text(if (state.apps.isEmpty()) "Request" else "Refresh") }
                    TextButton(
                        onClick = { copyAll() },
                        enabled = state.apps.isNotEmpty()
                    ) { Text("Copy all") }
                    TextButton(onClick = onClose) { Text("Close") }
                }
            }
        }
    }
}

@Composable
private fun AppRow(entry: AppInventory.Entry) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = entry.label,
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.weight(1f)
            )
            Text(
                text = if (entry.system) "system" else "user",
                style = MaterialTheme.typography.labelSmall,
                color = if (entry.system) {
                    MaterialTheme.colorScheme.onSurfaceVariant
                } else {
                    MaterialTheme.colorScheme.primary
                }
            )
        }
        Text(
            text = entry.packageName,
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = entry.version?.let { "v$it" } ?: "version unknown",
            style = MaterialTheme.typography.labelSmall
        )
    }
}

private enum class AppFilter(val title: String) {
    ALL("All"),
    USER("User"),
    SYSTEM("System");

    fun count(entries: List<AppInventory.Entry>): Int = when (this) {
        ALL -> entries.size
        USER -> entries.count { !it.system }
        SYSTEM -> entries.count { it.system }
    }
}

@Composable
private fun EndedCard(reason: String?, onDone: () -> Unit, modifier: Modifier = Modifier) {
    Card(modifier = modifier.padding(24.dp)) {
        Column(modifier = Modifier.padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Text("Session ended", style = MaterialTheme.typography.titleMedium)
            Text(
                text = reason ?: "session_end",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 6.dp)
            )
            Button(onClick = onDone, modifier = Modifier.padding(top = 16.dp)) {
                Text("Return")
            }
        }
    }
}

@Composable
private fun KeyboardDialog(onSend: (String) -> Unit, onDismiss: () -> Unit) {
    var text by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Send text") },
        text = {
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                label = { Text("Text typed into the focused field on the agent") }
            )
        },
        confirmButton = {
            TextButton(
                onClick = { onSend(text) },
                enabled = text.isNotEmpty()
            ) { Text("Send") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}
