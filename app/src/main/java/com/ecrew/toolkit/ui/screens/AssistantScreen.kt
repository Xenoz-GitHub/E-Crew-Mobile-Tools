package com.ecrew.toolkit.ui.screens

import android.content.Context
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.ecrew.toolkit.ai.AiContext
import com.ecrew.toolkit.ai.AiModelAssets
import com.ecrew.toolkit.ai.EngineState
import com.ecrew.toolkit.ai.XairexEngine
import com.ecrew.toolkit.ai.XairexEvent
import com.ecrew.toolkit.ai.XairexPrompt
import com.ecrew.toolkit.messaging.AiMessageRow
import com.ecrew.toolkit.messaging.AiRole
import com.ecrew.toolkit.messaging.MessagingDb
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Locale

/**
 * Xairex (Component 12): the pinned offline-assistant entry on the Chat home and its
 * conversation thread. UI only - generation runs through the process-wide
 * [XairexEngine] and the transcript lives in messages.db (ai_messages). See
 * notes/2026-10-19-1131-ai-assistant-design.md.
 */

@Composable
internal fun XairexCard(onOpen: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 12.dp)
            .clickable(onClick = onOpen)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(12.dp)
        ) {
            Icon(Icons.Default.AutoAwesome, contentDescription = null, tint = AccentGood)
            Column(modifier = Modifier.weight(1f).padding(start = 10.dp)) {
                Text("Xairex", style = MaterialTheme.typography.titleSmall)
                Text(
                    text = "Offline AI assistant - runs entirely on this device",
                    style = MaterialTheme.typography.bodySmall,
                    color = MonoGray
                )
            }
            Text("Open", style = MaterialTheme.typography.labelMedium, color = AccentInfo)
        }
    }
}

@Composable
internal fun XairexThread(
    db: MessagingDb,
    appContext: Context,
    scope: CoroutineScope,
    initialContext: AiContext?,
    onContextHandled: () -> Unit,
    onBack: () -> Unit
) {
    val engine = remember { XairexEngine.get() }
    val engineState by engine.state.collectAsState()
    val listState = rememberLazyListState()

    var messages by remember { mutableStateOf<List<AiMessageRow>>(emptyList()) }
    var draft by rememberSaveable { mutableStateOf("") }
    var context by remember { mutableStateOf(initialContext) }
    var streaming by remember { mutableStateOf<String?>(null) }
    var metaText by remember { mutableStateOf<String?>(null) }
    var failure by remember { mutableStateOf<String?>(null) }
    var clearOpen by remember { mutableStateOf(false) }
    var aboutOpen by remember { mutableStateOf(false) }

    val engineLabel = remember { engine.engineLabel() }

    DisposableEffect(Unit) {
        onDispose {
            // Leaving the thread releases the model so RAM returns to baseline.
            engine.stop()
            engine.requestUnload()
        }
    }
    LaunchedEffect(Unit) {
        messages = withContext(Dispatchers.IO) { db.aiMessages() }
        engine.ensureReady(appContext)
    }

    val generating = engineState is EngineState.Generating

    fun send() {
        if (generating) return
        if (engineState !is EngineState.Ready) return
        val text = draft.trim()
        if (text.isEmpty() || text.length > XairexPrompt.MAX_INPUT_CHARS) return
        val contextSnapshot = context
        draft = ""
        context = null
        if (contextSnapshot != null) onContextHandled()
        failure = null
        metaText = null
        scope.launch {
            withContext(Dispatchers.IO) {
                db.appendAiMessage(AiRole.USER, text, System.currentTimeMillis())
            }
            val history = withContext(Dispatchers.IO) { db.aiMessages() }
            messages = history
            streaming = ""
            engine.generate(XairexPrompt.build(history, contextSnapshot)).collect { event ->
                when (event) {
                    is XairexEvent.Token -> streaming = streaming.orEmpty() + event.text
                    is XairexEvent.Finished -> {
                        val body = streaming.orEmpty()
                        streaming = null
                        if (body.isNotBlank()) {
                            withContext(Dispatchers.IO) {
                                db.appendAiMessage(
                                    AiRole.ASSISTANT, body, System.currentTimeMillis()
                                )
                            }
                        }
                        val seconds = event.elapsedMs / 1000.0
                        metaText = when {
                            body.isBlank() -> "No reply was produced."
                            seconds <= 0.0 -> null
                            else -> String.format(
                                Locale.US, "%d tokens - %.1f s - %.1f tokens/s",
                                event.tokens, seconds, event.tokens / seconds
                            )
                        }
                    }
                    is XairexEvent.Failed -> {
                        val body = streaming.orEmpty()
                        streaming = null
                        if (body.isNotBlank()) {
                            withContext(Dispatchers.IO) {
                                db.appendAiMessage(
                                    AiRole.ASSISTANT, body, System.currentTimeMillis()
                                )
                            }
                        }
                        failure = event.message
                    }
                }
            }
            messages = withContext(Dispatchers.IO) { db.aiMessages() }
        }
    }

    val itemCount = messages.size + (if (generating) 1 else 0) + (if (metaText != null) 1 else 0)
    LaunchedEffect(itemCount, streaming?.length) {
        if (itemCount > 0) listState.scrollToItem(itemCount - 1)
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(start = 4.dp, top = 6.dp, end = 4.dp)
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back")
            }
            Column(modifier = Modifier.weight(1f)) {
                Text("Xairex", style = MaterialTheme.typography.titleMedium)
                Text(
                    text = AiModelAssets.MODEL_DISPLAY_NAME + " - offline on this device",
                    style = MaterialTheme.typography.labelSmall,
                    color = MonoGray
                )
            }
            IconButton(onClick = { aboutOpen = true }) {
                Icon(Icons.Default.Info, contentDescription = "About Xairex")
            }
            IconButton(onClick = { clearOpen = true }) {
                Icon(Icons.Default.DeleteSweep, contentDescription = "Clear conversation")
            }
        }

        when (val state = engineState) {
            is EngineState.Extracting -> ModelStatus(
                text = "Preparing the model (first run)... " +
                    (state.progress * 100).toInt() + "%",
                showBar = true,
                progress = state.progress
            )
            is EngineState.Loading -> ModelStatus(
                text = "Loading the model...",
                showBar = false,
                progress = 0f
            )
            is EngineState.Error -> Card(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp)
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(
                        text = state.message,
                        style = MaterialTheme.typography.bodySmall,
                        color = AccentBad
                    )
                    TextButton(
                        onClick = { scope.launch { engine.ensureReady(appContext) } }
                    ) { Text("Retry") }
                }
            }
            else -> Unit
        }

        val pendingContext = context
        if (pendingContext != null) {
            Surface(
                color = MaterialTheme.colorScheme.secondaryContainer,
                shape = RoundedCornerShape(10.dp),
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)
            ) {
                Column(modifier = Modifier.padding(10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "Attached: " + pendingContext.title,
                            style = MaterialTheme.typography.labelMedium,
                            modifier = Modifier.weight(1f)
                        )
                        TextButton(
                            onClick = {
                                context = null
                                onContextHandled()
                            }
                        ) { Text("Remove") }
                    }
                    Text(
                        text = pendingContext.body,
                        style = MaterialTheme.typography.bodySmall,
                        color = MonoGray,
                        maxLines = 3
                    )
                    Text(
                        text = "Sent with your next message only.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MonoGray
                    )
                }
            }
        }

        LazyColumn(
            state = listState,
            modifier = Modifier.weight(1f).fillMaxWidth().padding(horizontal = 12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            if (messages.isEmpty() && !generating) {
                item(key = "welcome") {
                    Text(
                        text = "Xairex is a small language model that runs entirely on this " +
                            "device. It can help with WPS findings, capture summaries and case " +
                            "notes - and it can be wrong.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MonoGray,
                        modifier = Modifier.padding(top = 12.dp)
                    )
                }
            }
            items(messages, key = { it.id }) { row -> AiBubble(row) }
            if (generating) {
                item(key = "stream") { StreamingBubble(text = streaming.orEmpty()) }
            }
            val meta = metaText
            if (meta != null && !generating) {
                item(key = "meta") {
                    Text(
                        text = meta,
                        style = MaterialTheme.typography.labelSmall,
                        color = MonoGray,
                        textAlign = TextAlign.End,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }

        val fail = failure
        if (fail != null) {
            Text(
                text = fail,
                style = MaterialTheme.typography.labelSmall,
                color = AccentBad,
                modifier = Modifier.padding(horizontal = 12.dp)
            )
        }
        Text(
            text = "Xairex runs on this device and can be wrong - verify important results.",
            style = MaterialTheme.typography.labelSmall,
            color = MonoGray,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 2.dp)
        )
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(8.dp)
        ) {
            OutlinedTextField(
                value = draft,
                onValueChange = { draft = it.take(XairexPrompt.MAX_INPUT_CHARS + 64) },
                modifier = Modifier.weight(1f),
                placeholder = { Text("Ask Xairex") },
                maxLines = 4,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                keyboardActions = KeyboardActions(onSend = { send() })
            )
            if (generating) {
                IconButton(onClick = { engine.stop() }) {
                    Icon(Icons.Default.Stop, contentDescription = "Stop")
                }
            } else {
                IconButton(
                    onClick = { send() },
                    enabled = engineState is EngineState.Ready &&
                        draft.isNotBlank() &&
                        draft.trim().length <= XairexPrompt.MAX_INPUT_CHARS
                ) {
                    Icon(Icons.Default.Send, contentDescription = "Send")
                }
            }
        }
        if (draft.trim().length > XairexPrompt.MAX_INPUT_CHARS) {
            Text(
                text = "Messages are limited to ${XairexPrompt.MAX_INPUT_CHARS} characters",
                style = MaterialTheme.typography.labelSmall,
                color = AccentBad,
                modifier = Modifier.padding(start = 12.dp, bottom = 6.dp)
            )
        }
    }

    if (clearOpen) {
        AlertDialog(
            onDismissRequest = { clearOpen = false },
            title = { Text("Delete this conversation?") },
            text = {
                Text(
                    "The whole Xairex transcript is removed from this device. Peer chats and " +
                        "case data are not affected."
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        clearOpen = false
                        scope.launch {
                            withContext(Dispatchers.IO) { db.clearAiMessages() }
                            messages = withContext(Dispatchers.IO) { db.aiMessages() }
                            metaText = null
                            failure = null
                        }
                    }
                ) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { clearOpen = false }) { Text("Cancel") } }
        )
    }
    if (aboutOpen) {
        AlertDialog(
            onDismissRequest = { aboutOpen = false },
            title = { Text("About Xairex") },
            text = {
                Column {
                    Text(
                        "A fully offline assistant: the language model runs on this device " +
                            "and nothing is sent anywhere.",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Text(
                        text = "Engine: $engineLabel (MIT license).",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(top = 6.dp)
                    )
                    Text(
                        text = "Model: ${AiModelAssets.MODEL_DISPLAY_NAME} " +
                            "(${AiModelAssets.MODEL_LICENSE}, from ${AiModelAssets.MODEL_SOURCE}).",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(top = 6.dp)
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { aboutOpen = false }) { Text("Close") }
            }
        )
    }
}

@Composable
private fun ModelStatus(text: String, showBar: Boolean, progress: Float) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp)
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            color = MonoGray,
            modifier = Modifier.padding(start = 8.dp).weight(1f)
        )
    }
    if (showBar) {
        LinearProgressIndicator(
            progress = progress,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)
        )
    }
}

@Composable
private fun AiBubble(row: AiMessageRow) {
    val user = row.role == AiRole.USER
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = if (user) Alignment.End else Alignment.Start
    ) {
        Surface(
            color = if (user) MaterialTheme.colorScheme.primaryContainer
            else MaterialTheme.colorScheme.surfaceVariant,
            shape = RoundedCornerShape(10.dp),
            modifier = Modifier.widthIn(max = 340.dp)
        ) {
            Column(modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)) {
                Text(row.body, style = MaterialTheme.typography.bodyMedium)
                Text(
                    text = formatStamp(row.ts),
                    style = MaterialTheme.typography.labelSmall,
                    color = MonoGray
                )
            }
        }
    }
}

@Composable
private fun StreamingBubble(text: String) {
    Column(modifier = Modifier.fillMaxWidth(), horizontalAlignment = Alignment.Start) {
        Surface(
            color = MaterialTheme.colorScheme.surfaceVariant,
            shape = RoundedCornerShape(10.dp),
            modifier = Modifier.widthIn(max = 340.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
            ) {
                if (text.isEmpty()) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(14.dp),
                        strokeWidth = 2.dp
                    )
                    Text(
                        text = "Working...",
                        style = MaterialTheme.typography.bodySmall,
                        color = MonoGray,
                        modifier = Modifier.padding(start = 8.dp)
                    )
                } else {
                    Text(text, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}
