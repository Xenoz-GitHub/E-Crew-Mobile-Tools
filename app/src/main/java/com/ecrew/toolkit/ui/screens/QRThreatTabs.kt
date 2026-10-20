package com.ecrew.toolkit.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ecrew.toolkit.util.Blocklist
import com.ecrew.toolkit.util.ParsedPayload
import com.ecrew.toolkit.util.YaraEngine

@Composable
fun QrIndicatorsTab(p: ParsedPayload) {
    val i = p.iocs
    SectionHeader("Extracted indicators (offline regex)", i.totalSize())
    if (i.totalSize() == 0) {
        MonoText("  no indicators found")
        return
    }
    StringList("URLs", i.urls, AccentInfo)
    StringList("Domains", i.domains, AccentInfo)
    StringList("IPv4 addresses", i.ips, AccentInfo)
    StringList("Emails", i.emails, AccentWarn)
    StringList("MD5", i.md5, MonoGray)
    StringList("SHA-1", i.sha1, MonoGray)
    StringList("SHA-256", i.sha256, MonoGray)
    StringList("Credential params", i.credentials, AccentBad)
}

@Composable
fun QrThreatsTab(p: ParsedPayload) {
    SectionHeader("Engine status", color = MonoGray)
    KeyValue("YARA rules", "${YaraEngine.ruleCount()} loaded, ${YaraEngine.errors().size} failed")
    KeyValue("Blocklist", "${Blocklist.size()} domains")
    YaraEngine.errors().take(5).forEach { MonoText("  ! $it", color = AccentWarn) }

    SectionHeader(
        "YARA matches",
        p.yaraMatches.size,
        if (p.yaraMatches.isEmpty()) AccentGood else AccentBad
    )
    if (p.yaraMatches.isEmpty()) MonoText("  no rule matched", color = AccentGood)
    p.yaraMatches.forEach { m ->
        Card(
            Modifier.fillMaxWidth().padding(vertical = 4.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF2A1B1D))
        ) {
            Column(Modifier.padding(8.dp)) {
                Text(
                    m.rule.uppercase(),
                    color = when (m.severity.lowercase()) {
                        "critical", "high" -> AccentBad
                        "medium" -> AccentWarn
                        else -> AccentInfo
                    },
                    fontSize = 13.sp
                )
                KeyValue("Severity", m.severity)
                KeyValue("Why", m.description)
                KeyValue("String", "\$${m.stringId}")
                MonoText("  value: ${m.matchedValue} @ 0x${m.offset.toString(16)}")
            }
        }
    }

    SectionHeader(
        "Blocklist matches",
        p.blocklistHits.size,
        if (p.blocklistHits.isEmpty()) AccentGood else AccentBad
    )
    if (p.blocklistHits.isEmpty()) MonoText("  no domain matched the offline blocklist", color = AccentGood)
    p.blocklistHits.forEach { MonoText("  BLOCKED: $it", color = AccentBad) }
}

