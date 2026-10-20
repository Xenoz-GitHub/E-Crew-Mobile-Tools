package com.ecrew.toolkit.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.ecrew.toolkit.remote.RemoteAudit
import com.ecrew.toolkit.remote.RemoteSessionDb
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Audit screen (spec Component 8): one row per session from the local database plus an
 * export of the merged per-message JSONL to Downloads/E-Crew/audit (MediaStore on API 29+,
 * legacy public Downloads with a media scan on API 26-28).
 */
@Composable
fun RemoteAuditScreen() {
    val context = LocalContext.current
    var rows by remember { mutableStateOf<List<RemoteSessionDb.Row>>(emptyList()) }
    var status by remember { mutableStateOf<String?>(null) }
    var reloadTick by remember { mutableIntStateOf(0) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(reloadTick) {
        rows = withContext(Dispatchers.IO) {
            RemoteSessionDb(context.applicationContext).listRecent()
        }
    }

    fun export() {
        scope.launch {
            status = "Exporting..."
            val result = withContext(Dispatchers.IO) {
                RemoteAudit.exportAll(
                    context.applicationContext,
                    RemoteSessionDb(context.applicationContext)
                )
            }
            status = result.fold(
                onSuccess = { path -> "Exported: $path" },
                onFailure = { error -> "Export failed: ${error.message ?: error.javaClass.simpleName}" }
            )
            reloadTick += 1
        }
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            export()
        } else {
            status = "Storage permission denied - cannot write into Downloads on this Android version."
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = "Session audit",
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.weight(1f)
            )
            IconButton(onClick = { reloadTick += 1 }) {
                Icon(Icons.Default.Refresh, contentDescription = "Refresh")
            }
        }
        Text(
            text = "${rows.size} session(s). Every session has one database row here and a " +
                "per-message JSONL file in the app's audit directory.",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 4.dp)
        )
        Button(
            onClick = {
                val needsLegacyPermission = Build.VERSION.SDK_INT < 29 &&
                    ContextCompat.checkSelfPermission(
                        context, Manifest.permission.WRITE_EXTERNAL_STORAGE
                    ) != PackageManager.PERMISSION_GRANTED
                if (needsLegacyPermission) {
                    permissionLauncher.launch(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                } else {
                    export()
                }
            },
            modifier = Modifier.padding(top = 12.dp)
        ) {
            Text("Export to Downloads/E-Crew/audit")
        }
        status?.let { text ->
            Text(
                text = text,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 8.dp)
            )
        }

        if (rows.isEmpty()) {
            Text(
                text = "No remote-support sessions recorded yet.",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(top = 24.dp)
            )
        } else {
            rows.forEach { row -> SessionRowCard(row) }
        }
    }
}

@Composable
private fun SessionRowCard(row: RemoteSessionDb.Row) {
    val format = remember { SimpleDateFormat("MM-dd HH:mm:ss", Locale.US) }
    val started = format.format(Date(row.startedAt))
    val durationSeconds = ((row.endedAt ?: System.currentTimeMillis()) - row.startedAt) / 1000
    Card(modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(row.peer, style = MaterialTheme.typography.titleSmall)
            Text(
                text = "${row.transport} - started $started - ${durationSeconds}s",
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                text = "in ${row.bytesIn / 1024} KB / out ${row.bytesOut / 1024} KB / " +
                    "${row.frames} frames",
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                text = "id ${row.sessionId.take(8)} - end: ${row.endReason ?: "in progress"}",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace
            )
        }
    }
}
