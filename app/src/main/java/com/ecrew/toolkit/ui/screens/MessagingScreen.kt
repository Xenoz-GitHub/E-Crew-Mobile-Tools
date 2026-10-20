package com.ecrew.toolkit.ui.screens

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Send
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.ecrew.toolkit.ai.AiContext
import com.ecrew.toolkit.ai.AiIntake
import com.ecrew.toolkit.messaging.BluetoothLink
import com.ecrew.toolkit.messaging.BtDeviceInfo
import com.ecrew.toolkit.messaging.Conversation
import com.ecrew.toolkit.messaging.Fingerprints
import com.ecrew.toolkit.messaging.IdentityStore
import com.ecrew.toolkit.messaging.MessagingBus
import com.ecrew.toolkit.messaging.MessagingDb
import com.ecrew.toolkit.messaging.MessagingPrefs
import com.ecrew.toolkit.messaging.MessagingProtocol
import com.ecrew.toolkit.messaging.MessagingService
import com.ecrew.toolkit.messaging.MsgDirection
import com.ecrew.toolkit.messaging.MsgState
import com.ecrew.toolkit.messaging.MsgTransport
import com.ecrew.toolkit.messaging.MessageRow
import com.ecrew.toolkit.messaging.NearbyPeer
import com.ecrew.toolkit.messaging.PeerRow
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

/**
 * Chat (Component 11): visibility toggle, nearby users (LAN + Bluetooth), conversation
 * list and threads with Queued/Sent/Delivered states. The screen writes only to
 * messages.db and observes [MessagingBus]; all sockets live in MessagingService.
 */
@Composable
fun MessagingScreen() {
    val context = LocalContext.current
    val appContext = context.applicationContext
    val prefs = remember { MessagingPrefs(appContext) }
    val db = remember { MessagingDb.get(appContext) }
    val scope = rememberCoroutineScope()

    var openPeer by rememberSaveable { mutableStateOf<String?>(null) }
    var conversations by remember { mutableStateOf<List<Conversation>>(emptyList()) }
    var locationGranted by remember { mutableStateOf(hasLocationPermission(context)) }
    var pendingScan by remember { mutableStateOf(false) }
    var editNameOpen by remember { mutableStateOf(false) }
    var openXairex by rememberSaveable { mutableStateOf(false) }
    var xairexContext by remember { mutableStateOf<AiContext?>(null) }

    val revision = MessagingBus.revision
    val nearby = MessagingBus.nearby
    val visible = MessagingBus.visible
    val statusText = MessagingBus.statusText
    val btScanning = MessagingBus.btScanning
    val btDiscovered = MessagingBus.btDiscovered
    val btBusyAddress = MessagingBus.btBusyAddress

    val locationLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        locationGranted = granted
        if (granted && pendingScan) {
            pendingScan = false
            MessagingService.scanBt(appContext)
        } else if (!granted) {
            MessagingBus.setStatus("Location permission is required for Bluetooth scanning")
        }
    }
    val discoverableLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode != Activity.RESULT_CANCELED) {
            MessagingBus.setStatus("Discoverable for about 2 minutes - pair from the other device now")
        } else {
            MessagingBus.setStatus("The discoverable request was declined")
        }
    }

    DisposableEffect(Unit) {
        MessagingBus.screenActive = true
        MessagingService.listen(appContext)
        onDispose {
            MessagingBus.screenActive = false
            MessagingService.screenClosed(appContext)
        }
    }
    LaunchedEffect(Unit) {
        MessagingBus.visible = prefs.visible
    }
    LaunchedEffect(revision, openPeer) {
        conversations = withContext(Dispatchers.IO) { db.conversations() }
    }
    LaunchedEffect(openPeer) {
        val peer = openPeer ?: return@LaunchedEffect
        withContext(Dispatchers.IO) { db.markRead(peer) }
        MessagingBus.bump()
    }
    LaunchedEffect(Unit) {
        // "Ask Xairex": a result screen handed text to the assistant and asked for Chat.
        if (AiIntake.openRequested) {
            AiIntake.openRequested = false
            xairexContext = AiIntake.consumePending()
            openXairex = true
        }
    }

    fun setVisible(on: Boolean) {
        MessagingBus.visible = on
        prefs.visible = on
        if (on) {
            MessagingService.enableVisible(appContext)
        } else {
            MessagingService.listen(appContext)
        }
    }

    fun startBtScan() {
        if (!locationGranted) {
            pendingScan = true
            locationLauncher.launch(Manifest.permission.ACCESS_FINE_LOCATION)
            return
        }
        MessagingService.scanBt(appContext)
    }

    val peerId = openPeer
    if (openXairex) {
        XairexThread(
            db = db,
            appContext = appContext,
            scope = scope,
            initialContext = xairexContext,
            onContextHandled = { xairexContext = null },
            onBack = { openXairex = false }
        )
    } else if (peerId == null) {
        ChatHome(
            prefs = prefs,
            conversations = conversations,
            nearby = nearby,
            visible = visible,
            statusText = statusText,
            btScanning = btScanning,
            btDiscovered = btDiscovered,
            btBusyAddress = btBusyAddress,
            locationGranted = locationGranted,
            onToggleVisible = { setVisible(it) },
            onEditName = { editNameOpen = true },
            onOpenPeer = { openPeer = it },
            onOpenXairex = {
                xairexContext = AiIntake.consumePending()
                openXairex = true
            },
            onConnectLan = { host, port -> MessagingService.identifyLan(appContext, host, port) },
            onScanBt = { startBtScan() },
            onMakeDiscoverable = { discoverableLauncher.launch(BluetoothLink.makeDiscoverableIntent()) },
            onPairBt = { MessagingService.pairBt(appContext, it) },
            onProbeBt = { MessagingService.probeBt(appContext, it) }
        )
    } else {
        ChatThread(
            peerId = peerId,
            db = db,
            appContext = appContext,
            scope = scope,
            onBack = { openPeer = null }
        )
    }

    if (editNameOpen) {
        NameDialog(
            current = prefs.displayName,
            onDismiss = { editNameOpen = false },
            onSave = { name ->
                prefs.displayName = name
                MessagingBus.setStatus("Display name updated; it is announced on the next session")
                editNameOpen = false
            }
        )
    }
}

// ---------------------------------------------------------------- home

@Composable
private fun ChatHome(
    prefs: MessagingPrefs,
    conversations: List<Conversation>,
    nearby: List<NearbyPeer>,
    visible: Boolean,
    statusText: String?,
    btScanning: Boolean,
    btDiscovered: List<BtDeviceInfo>,
    btBusyAddress: String?,
    locationGranted: Boolean,
    onToggleVisible: (Boolean) -> Unit,
    onEditName: () -> Unit,
    onOpenPeer: (String) -> Unit,
    onOpenXairex: () -> Unit,
    onConnectLan: (String, Int) -> Unit,
    onScanBt: () -> Unit,
    onMakeDiscoverable: () -> Unit,
    onPairBt: (String) -> Unit,
    onProbeBt: (String) -> Unit
) {
    val appContext = LocalContext.current.applicationContext
    var ownFingerprint by remember { mutableStateOf("") }
    LaunchedEffect(Unit) {
        ownFingerprint = withContext(Dispatchers.IO) { IdentityStore.load(appContext).fingerprint }
    }
    val name = prefs.displayName
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        Text(
            text = "Chat",
            style = MaterialTheme.typography.titleLarge
        )
        Text(
            text = if (visible) {
                "Visible to nearby users on Wi-Fi and Bluetooth"
            } else {
                "Listening quietly while this screen is open"
            },
            style = MaterialTheme.typography.bodySmall,
            color = AccentInfo,
            modifier = Modifier.padding(top = 2.dp)
        )
        statusText?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodySmall,
                color = MonoGray,
                modifier = Modifier.padding(top = 4.dp)
            )
        }

        XairexCard(onOpen = onOpenXairex)

        Card(modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Visible to nearby users", style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                    Switch(checked = visible, onCheckedChange = onToggleVisible)
                }
                Text(
                    text = "Off (default): you can still message others while this screen is open. " +
                        "On: the app keeps listening in the background and announces your presence.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MonoGray
                )
            }
        }

        Card(modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("You", style = MaterialTheme.typography.titleSmall)
                    Spacer(modifier = Modifier.weight(1f))
                    TextButton(onClick = onEditName) { Text("Edit name") }
                }
                Text(name, style = MaterialTheme.typography.bodyMedium)
                Text(
                    text = if (ownFingerprint.isEmpty()) "loading..." else Fingerprints.group(ownFingerprint),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MonoGray
                )
                Text(
                    text = "Peers compare this fingerprint to verify you. It never changes unless the app " +
                        "data is erased.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MonoGray,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
        }

        Card(modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text("Nearby users", style = MaterialTheme.typography.titleSmall)
                if (nearby.isEmpty()) {
                    Text(
                        text = "No one found yet. Others appear here when they open E-Crew Chat on the " +
                            "same Wi-Fi or after a Bluetooth connect.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MonoGray,
                        modifier = Modifier.padding(top = 6.dp)
                    )
                } else {
                    nearby.take(20).forEach { peer ->
                        NearbyRow(peer = peer, onMessage = onOpenPeer, onConnectLan = onConnectLan)
                    }
                }
                if (!locationGranted) {
                    Text(
                        text = "Bluetooth scanning needs location permission; Wi-Fi discovery works " +
                            "without it.",
                        style = MaterialTheme.typography.labelSmall,
                        color = AccentWarn,
                        modifier = Modifier.padding(top = 6.dp)
                    )
                }
                Row(
                    modifier = Modifier.padding(top = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(onClick = onScanBt, enabled = !btScanning) {
                        Text(if (btScanning) "Scanning..." else "Scan Bluetooth")
                    }
                    OutlinedButton(onClick = onMakeDiscoverable) { Text("Discoverable 2 min") }
                }
                if (btScanning) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(top = 6.dp)
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                        Text(
                            text = "Looking for Bluetooth devices...",
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(start = 8.dp)
                        )
                    }
                }
                btDiscovered.forEach { device ->
                    BtDeviceRow(
                        device = device.copy(busy = device.address == btBusyAddress),
                        onPair = onPairBt,
                        onConnect = onProbeBt
                    )
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth().padding(top = 12.dp, bottom = 16.dp)) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text("Conversations", style = MaterialTheme.typography.titleSmall)
                if (conversations.isEmpty()) {
                    Text(
                        text = "No conversations yet. Send the first message from a nearby user.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MonoGray,
                        modifier = Modifier.padding(top = 6.dp)
                    )
                } else {
                    conversations.forEach { conversation ->
                        ConversationRow(
                            conversation = conversation,
                            onOpen = { onOpenPeer(conversation.peer.id) }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun NearbyRow(
    peer: NearbyPeer,
    onMessage: (String) -> Unit,
    onConnectLan: (String, Int) -> Unit
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(peer.name, style = MaterialTheme.typography.bodyMedium)
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = peer.transport.label,
                    style = MaterialTheme.typography.labelSmall,
                    color = if (peer.transport == MsgTransport.WIFI) AccentInfo else AccentGood
                )
                if (peer.verified) {
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("verified", style = MaterialTheme.typography.labelSmall, color = AccentGood)
                }
            }
            Text(
                text = if (peer.fingerprint != null) Fingerprints.short(peer.fingerprint)
                else (peer.host ?: "") + (if (peer.port > 0) ":" + peer.port else ""),
                style = MaterialTheme.typography.labelSmall,
                fontFamily = FontFamily.Monospace,
                color = MonoGray
            )
        }
        if (peer.fingerprint != null) {
            TextButton(onClick = { onMessage(peer.id) }) { Text("Message") }
        } else if (peer.host != null && peer.port > 0) {
            TextButton(onClick = { onConnectLan(peer.host, peer.port) }) { Text("Connect") }
        }
    }
}

@Composable
private fun BtDeviceRow(
    device: BtDeviceInfo,
    onPair: (String) -> Unit,
    onConnect: (String) -> Unit
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(device.name, style = MaterialTheme.typography.bodyMedium)
            Text(
                text = device.address + (if (device.bonded) " - paired" else " - not paired"),
                style = MaterialTheme.typography.labelSmall,
                fontFamily = FontFamily.Monospace,
                color = MonoGray
            )
        }
        if (device.busy) {
            CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
        } else if (device.bonded) {
            TextButton(onClick = { onConnect(device.address) }) { Text("Connect") }
        } else {
            TextButton(onClick = { onPair(device.address) }) { Text("Pair") }
        }
    }
}

@Composable
private fun ConversationRow(conversation: Conversation, onOpen: () -> Unit) {
    val unread = conversation.unread > 0
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 10.dp)
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = conversation.peer.displayName,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = if (unread) FontWeight.Bold else FontWeight.Normal
            )
            Text(
                text = (if (conversation.lastOutgoing) "You: " else "") + conversation.lastBody,
                style = MaterialTheme.typography.bodySmall,
                color = MonoGray,
                maxLines = 1
            )
        }
        Column(horizontalAlignment = Alignment.End) {
            Text(
                text = formatStamp(conversation.lastTs),
                style = MaterialTheme.typography.labelSmall,
                color = MonoGray
            )
            if (unread) {
                Text(
                    text = conversation.unread.toString(),
                    style = MaterialTheme.typography.labelSmall,
                    color = AccentInfo,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }
        }
        TextButton(onClick = onOpen) { Text("Open") }
    }
}

// ---------------------------------------------------------------- thread

@Composable
private fun ChatThread(
    peerId: String,
    db: MessagingDb,
    appContext: Context,
    scope: kotlinx.coroutines.CoroutineScope,
    onBack: () -> Unit
) {
    val revision = MessagingBus.revision
    var peer by remember { mutableStateOf<PeerRow?>(null) }
    var messages by remember { mutableStateOf<List<MessageRow>>(emptyList()) }
    var draft by rememberSaveable { mutableStateOf("") }
    var verifyOpen by remember { mutableStateOf(false) }
    var blockOpen by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()

    LaunchedEffect(revision, peerId) {
        peer = withContext(Dispatchers.IO) { db.peer(peerId) }
        messages = withContext(Dispatchers.IO) { db.conversation(peerId) }
    }
    LaunchedEffect(messages.size, peerId) {
        if (messages.isNotEmpty()) listState.animateScrollToItem(messages.size - 1)
    }

    fun send() {
        val text = draft.trim()
        if (text.isEmpty()) return
        if (text.length > MessagingProtocol.MAX_MESSAGE_CHARS) return
        if (text.toByteArray(Charsets.UTF_8).size > MessagingProtocol.MAX_MESSAGE_BYTES) return
        draft = ""
        val now = System.currentTimeMillis()
        val row = MessageRow(
            id = UUID.randomUUID().toString(),
            peerId = peerId,
            direction = MsgDirection.OUT,
            body = text,
            ts = now,
            state = MsgState.QUEUED,
            attempts = 0,
            lastAttempt = 0L,
            read = true
        )
        scope.launch {
            withContext(Dispatchers.IO) {
                if (db.peer(peerId) == null) db.upsertPeer(peerId, "E-Crew user", now)
                db.insertMessage(row)
            }
            MessagingBus.bump()
        }
    }

    fun markVerified() {
        scope.launch {
            withContext(Dispatchers.IO) { db.setVerified(peerId, true) }
            MessagingService.refresh(appContext)
            MessagingBus.bump()
        }
        verifyOpen = false
    }

    fun setBlocked(blocked: Boolean) {
        scope.launch {
            withContext(Dispatchers.IO) { db.setBlocked(peerId, blocked) }
            MessagingService.refresh(appContext)
            MessagingBus.bump()
        }
        blockOpen = false
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(start = 4.dp, top = 6.dp, end = 12.dp)
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back")
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = peer?.displayName ?: "E-Crew user",
                    style = MaterialTheme.typography.titleMedium
                )
                Text(
                    text = Fingerprints.group(peerId),
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = MonoGray,
                    maxLines = 1,
                    fontSize = 9.sp
                )
            }
        }

        val current = peer
        when {
            current?.blocked == true -> StatusBar(
                text = "Blocked - messages from this peer are ignored",
                color = AccentBad,
                actionLabel = "Unblock",
                onAction = { setBlocked(false) }
            )
            current != null && !current.verified -> StatusBar(
                text = "New sender - not verified",
                color = AccentWarn,
                actionLabel = "Verify",
                onAction = { verifyOpen = true },
                secondLabel = "Block",
                onSecond = { blockOpen = true }
            )
            current?.verified == true -> StatusBar(
                text = "Verified peer",
                color = AccentGood,
                actionLabel = "Block",
                onAction = { blockOpen = true }
            )
        }

        LazyColumn(
            state = listState,
            modifier = Modifier.weight(1f).fillMaxWidth().padding(horizontal = 12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            items(messages, key = { it.id }) { row ->
                MessageBubble(row)
            }
        }

        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(8.dp)
        ) {
            OutlinedTextField(
                value = draft,
                onValueChange = { draft = it.take(MessagingProtocol.MAX_MESSAGE_CHARS + 64) },
                modifier = Modifier.weight(1f),
                placeholder = { Text("Message") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                keyboardActions = KeyboardActions(onSend = { send() })
            )
            IconButton(
                onClick = { send() },
                enabled = draft.isNotBlank() && draft.trim().length <= MessagingProtocol.MAX_MESSAGE_CHARS
            ) {
                Icon(Icons.Default.Send, contentDescription = "Send")
            }
        }
        if (draft.trim().length > MessagingProtocol.MAX_MESSAGE_CHARS) {
            Text(
                text = "Messages are limited to ${MessagingProtocol.MAX_MESSAGE_CHARS} characters",
                style = MaterialTheme.typography.labelSmall,
                color = AccentBad,
                modifier = Modifier.padding(start = 12.dp, bottom = 6.dp)
            )
        }
    }

    if (verifyOpen) {
        VerifyDialog(
            peerId = peerId,
            peerName = peer?.displayName ?: "this peer",
            onDismiss = { verifyOpen = false },
            onConfirm = { markVerified() }
        )
    }
    if (blockOpen) {
        AlertDialog(
            onDismissRequest = { blockOpen = false },
            title = { Text("Block this peer?") },
            text = {
                Text(
                    "Blocked peers cannot reach you (their sessions are closed silently), are hidden " +
                        "from the nearby list, and their past messages stay in this thread."
                )
            },
            confirmButton = { TextButton(onClick = { setBlocked(true) }) { Text("Block") } },
            dismissButton = { TextButton(onClick = { blockOpen = false }) { Text("Cancel") } }
        )
    }
}

@Composable
private fun StatusBar(
    text: String,
    color: androidx.compose.ui.graphics.Color,
    actionLabel: String,
    onAction: () -> Unit,
    secondLabel: String? = null,
    onSecond: (() -> Unit)? = null
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)
    ) {
        Text(text, style = MaterialTheme.typography.bodySmall, color = color, modifier = Modifier.weight(1f))
        TextButton(onClick = onAction) { Text(actionLabel) }
        if (secondLabel != null && onSecond != null) {
            TextButton(onClick = onSecond) { Text(secondLabel) }
        }
    }
}

@Composable
private fun MessageBubble(row: MessageRow) {
    val outgoing = row.direction == MsgDirection.OUT
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = if (outgoing) Alignment.End else Alignment.Start
    ) {
        Surface(
            color = if (outgoing) MaterialTheme.colorScheme.primaryContainer
            else MaterialTheme.colorScheme.surfaceVariant,
            shape = RoundedCornerShape(10.dp),
            modifier = Modifier.widthIn(max = 320.dp)
        ) {
            Column(modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)) {
                Text(row.body, style = MaterialTheme.typography.bodyMedium)
                Text(
                    text = if (outgoing) formatStamp(row.ts) + "  " + stateLabel(row.state)
                    else formatStamp(row.ts),
                    style = MaterialTheme.typography.labelSmall,
                    color = if (outgoing) stateColor(row.state) else MonoGray
                )
            }
        }
    }
}

@Composable
private fun VerifyDialog(
    peerId: String,
    peerName: String,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Compare fingerprints") },
        text = {
            Column {
                Text(
                    "Read this fingerprint to $peerName and compare it with the fingerprint shown " +
                        "in their Chat screen. Only continue when both are identical.",
                    style = MaterialTheme.typography.bodySmall
                )
                Text(
                    text = Fingerprints.group(peerId),
                    style = MaterialTheme.typography.titleMedium,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.padding(top = 10.dp)
                )
            }
        },
        confirmButton = { TextButton(onClick = onConfirm) { Text("They match") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

@Composable
private fun NameDialog(current: String, onDismiss: () -> Unit, onSave: (String) -> Unit) {
    var value by remember { mutableStateOf(current) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Display name") },
        text = {
            Column {
                Text(
                    "This name is announced to nearby E-Crew users while you are visible.",
                    style = MaterialTheme.typography.bodySmall
                )
                OutlinedTextField(
                    value = value,
                    onValueChange = { value = it.take(MessagingProtocol.MAX_NAME_CHARS) },
                    modifier = Modifier.padding(top = 8.dp),
                    singleLine = true
                )
            }
        },
        confirmButton = { TextButton(onClick = { onSave(value) }) { Text("Save") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

// ---------------------------------------------------------------- helpers

private fun hasLocationPermission(context: Context): Boolean =
    ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
        PackageManager.PERMISSION_GRANTED

internal fun stateLabel(state: String): String = when (state) {
    MsgState.QUEUED -> "Queued"
    MsgState.SENT -> "Sent"
    MsgState.DELIVERED -> "Delivered"
    MsgState.FAILED -> "Not delivered"
    else -> ""
}

internal fun stateColor(state: String): androidx.compose.ui.graphics.Color = when (state) {
    MsgState.DELIVERED -> AccentGood
    MsgState.FAILED -> AccentBad
    else -> MonoGray
}

internal fun formatStamp(ts: Long): String {
    val now = System.currentTimeMillis()
    val format = if (now - ts < 24L * 60 * 60 * 1000 && now >= ts) "HH:mm" else "MM-dd HH:mm"
    return SimpleDateFormat(format, Locale.US).format(Date(ts))
}
