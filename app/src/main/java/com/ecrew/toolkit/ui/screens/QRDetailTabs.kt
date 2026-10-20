package com.ecrew.toolkit.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ecrew.toolkit.util.ParsedPayload

@Composable
internal fun MonoText(text: String, color: Color = Color(0xFFCFD8DC)) {
    Text(
        text,
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        color = color
    )
}

@Composable
internal fun SectionHeader(title: String, count: Int? = null, color: Color = AccentInfo) {
    Text(
        if (count != null) "$title ($count)" else title,
        color = color,
        fontSize = 13.sp,
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.padding(top = 10.dp, bottom = 4.dp)
    )
}

@Composable
internal fun KeyValue(key: String, value: String, valueColor: Color = Color(0xFFCFD8DC)) {
    Row(Modifier.fillMaxWidth().padding(vertical = 1.dp)) {
        Text("$key:", fontSize = 12.sp, color = MonoGray, modifier = Modifier.width(96.dp))
        Text(value, fontSize = 12.sp, color = valueColor, fontFamily = FontFamily.Monospace)
    }
}

@Composable
internal fun StringList(title: String, items: List<String>, color: Color = Color(0xFFCFD8DC)) {
    if (items.isEmpty()) return
    SectionHeader(title, items.size, color)
    items.forEach { MonoText("  $it", color = color) }
}

// ------------------------------------------------------------------ tabs

@Composable
fun QrOverviewTab(p: ParsedPayload) {
    SectionHeader("Raw payload")
    MonoText(p.original)

    val u = p.urlInfo
    if (u != null) {
        SectionHeader("URL decomposition", color = AccentGood)
        KeyValue("Scheme", u.scheme ?: "-")
        KeyValue("User info", u.userInfo ?: "-", if (u.userInfo != null) AccentWarn else MonoGray)
        KeyValue("Host", u.host ?: "-")
        KeyValue("Port", u.port?.toString() ?: "(default)")
        KeyValue("Path", u.path ?: "/")
        KeyValue("Fragment", u.fragment ?: "-")
        if (u.query.isNotEmpty()) {
            SectionHeader("Query parameters", u.query.size, AccentWarn)
            u.query.forEach { (k, v) -> KeyValue(k, v) }
        }
    } else {
        SectionHeader("URL decomposition")
        MonoText("  no URL found in payload or decoded layers")
    }

    SectionHeader("Quick counts")
    KeyValue("Decode layers", p.layers.size.toString())
    KeyValue("URLs", p.urls.size.toString())
    KeyValue("IOCs", p.iocs.totalSize().toString())
    KeyValue("YARA hits", p.yaraMatches.size.toString())
    KeyValue("Blocklist hits", p.blocklistHits.size.toString())
}

@Composable
fun QrLayersTab(p: ParsedPayload) {
    if (p.layers.isEmpty()) {
        SectionHeader("Decoded layers")
        MonoText("  payload contains no nested encodings")
        return
    }
    SectionHeader("Decoded layers", p.layers.size, AccentGood)
    p.layers.forEach { step ->
        Card(
            Modifier.fillMaxWidth().padding(vertical = 4.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1A2229))
        ) {
            Column(Modifier.padding(8.dp)) {
                Text("Layer ${step.layer} — ${step.encoding}", color = AccentGood, fontSize = 12.sp)
                Spacer(Modifier.height(4.dp))
                MonoText(step.value, color = if (step.isBinary) AccentWarn else Color(0xFFCFD8DC))
            }
        }
    }
}

@Composable
fun QrHexTab(p: ParsedPayload) {
    SectionHeader("Hex dump (UTF-8 bytes of original payload)")
    MonoText(p.hexDump)
}

@Composable
fun QrCborTab(p: ParsedPayload) {
    SectionHeader("CBOR inspector (RFC 8949)")
    val tree = p.cborTree
    if (tree == null) {
        MonoText("  payload is not a well-formed CBOR structure", color = MonoGray)
    } else {
        MonoText(tree, color = AccentGood)
    }
}

