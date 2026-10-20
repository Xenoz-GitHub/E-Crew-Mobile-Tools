package com.ecrew.toolkit.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Backspace
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ecrew.toolkit.remote.RemotePhase
import com.ecrew.toolkit.remote.RemoteSessionController
import com.ecrew.toolkit.remote.RemoteTarget

/**
 * Pair screen (spec Component 6): target summary (or manual IP entry) plus a custom
 * 6-digit PIN keypad. Deliberately no OS keyboard and no autofill: the pairing code is
 * read aloud by the device owner and typed on this keypad.
 */
@Composable
fun RemotePairScreen(
    controller: RemoteSessionController,
    pendingTarget: RemoteTarget?,
    onClearTarget: () -> Unit
) {
    var host by remember { mutableStateOf("") }
    var portText by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    val state = controller.state.value

    val manualPort = portText.toIntOrNull()
    val manualTarget: RemoteTarget.Lan? =
        if (host.isNotBlank() && manualPort != null && manualPort in 1..65535) {
            RemoteTarget.Lan("Manual entry", host.trim(), manualPort)
        } else {
            null
        }
    val target: RemoteTarget? = pendingTarget ?: manualTarget

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        Text("Pair with an agent", style = MaterialTheme.typography.titleLarge)
        Text(
            text = "Ask the device owner to read you the 6-digit code shown on their screen " +
                "(and in their persistent notification), then enter it below.",
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(top = 8.dp)
        )

        Card(modifier = Modifier.fillMaxWidth().padding(top = 16.dp)) {
            Column(modifier = Modifier.padding(12.dp)) {
                if (pendingTarget != null) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Target", style = MaterialTheme.typography.labelMedium)
                            Text(pendingTarget.label, style = MaterialTheme.typography.bodyMedium)
                        }
                        IconButton(onClick = onClearTarget) {
                            Icon(Icons.Default.Close, contentDescription = "Clear target")
                        }
                    }
                } else {
                    Text("Manual LAN target", style = MaterialTheme.typography.labelMedium)
                    OutlinedTextField(
                        value = host,
                        onValueChange = { host = it },
                        label = { Text("Host or IP") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
                    )
                    OutlinedTextField(
                        value = portText,
                        onValueChange = { typed -> portText = typed.filter { it.isDigit() }.take(5) },
                        label = { Text("Port") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
                    )
                    Text(
                        text = "Or pick a discovered device on the Discover tab.",
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.padding(top = 6.dp)
                    )
                }
            }
        }

        Text(
            text = "Pairing code",
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(top = 20.dp)
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            horizontalArrangement = Arrangement.Center
        ) {
            for (index in 0 until CODE_LENGTH) {
                val digit = code.getOrNull(index)?.toString() ?: "\u2013"
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    modifier = Modifier.padding(horizontal = 4.dp)
                ) {
                    Box(
                        modifier = Modifier.size(width = 44.dp, height = 56.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = digit,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 26.sp,
                            style = MaterialTheme.typography.titleLarge
                        )
                    }
                }
            }
        }

        Keypad(
            onDigit = { digit -> if (code.length < CODE_LENGTH) code += digit },
            onClear = { code = "" },
            onDelete = { code = code.dropLast(1) },
            modifier = Modifier.padding(top = 16.dp)
        )

        Button(
            onClick = {
                val selected = target ?: return@Button
                controller.start(selected, code)
            },
            enabled = target != null && code.length == CODE_LENGTH,
            modifier = Modifier.fillMaxWidth().padding(top = 20.dp)
        ) {
            Text("Connect")
        }

        if (state.phase == RemotePhase.IDLE && state.error != null) {
            Text(
                text = state.error,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 12.dp)
            )
        }
    }
}

@Composable
private fun Keypad(
    onDigit: (String) -> Unit,
    onClear: () -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier
) {
    val rows = listOf(
        listOf("1", "2", "3"),
        listOf("4", "5", "6"),
        listOf("7", "8", "9"),
        listOf("CLR", "0", "DEL")
    )
    Column(modifier = modifier.fillMaxWidth()) {
        rows.forEach { row ->
            Row(modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                row.forEach { key ->
                    OutlinedButton(
                        onClick = {
                            when (key) {
                                "CLR" -> onClear()
                                "DEL" -> onDelete()
                                else -> onDigit(key)
                            }
                        },
                        modifier = Modifier.weight(1f).padding(horizontal = 4.dp).height(56.dp)
                    ) {
                        if (key == "DEL") {
                            Icon(Icons.Default.Backspace, contentDescription = "Delete")
                        } else {
                            Text(key, style = MaterialTheme.typography.titleMedium)
                        }
                    }
                }
            }
        }
    }
}

private const val CODE_LENGTH = 6
