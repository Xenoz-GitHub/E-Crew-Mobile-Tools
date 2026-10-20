package com.ecrew.toolkit.ioc

import com.ecrew.toolkit.apk.Severity

data class IocArtifact(val path: String, val text: String)

data class IocMatch(
    val indicatorId: String,
    val indicatorName: String,
    val severity: Severity,
    val objectType: String,
    val value: String,
    val artifact: String,
    val evidence: String
)

data class IocScanResult(
    val matches: List<IocMatch>,
    val skippedPatterns: Int,
    val scannedArtifacts: Int,
    val warnings: List<String>
) {
    val highestSeverity: Severity?
        get() = matches.maxByOrNull { it.severity.rank }?.severity
}

/**
 * Matches the supported STIX subset against acquisition text artifacts. Evidence is one
 * bounded line with obvious secret fields redacted. Matches are de-duplicated by indicator,
 * artifact and evidence line.
 */
object IocEngine {
    private const val MAX_MATCHES = 1_000
    private const val MAX_EVIDENCE = 300
    private val sensitiveKeys = listOf(
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "cookie",
        "api_key",
        "apikey"
    )

    fun match(bundle: StixBundle, artifacts: List<IocArtifact>): IocScanResult {
        val matches = ArrayList<IocMatch>()
        val warnings = ArrayList<String>()
        for (artifact in artifacts) {
            if (matches.size >= MAX_MATCHES) {
                warnings.add("match cap reached")
                break
            }
            val lines = artifact.text.lineSequence().take(MAX_LINES)
            for (line in lines) {
                if (line.length > MAX_LINE) {
                    warnings.add("${artifact.path}: evidence line capped")
                    continue
                }
                for (indicator in bundle.indicators) {
                    if (indicator.rules.isEmpty()) continue
                    for (rule in indicator.rules) {
                        if (!matchesRule(rule, artifact.path, line)) continue
                        matches.add(
                            IocMatch(
                                indicatorId = indicator.id,
                                indicatorName = indicator.name,
                                severity = indicator.severity,
                                objectType = rule.objectType,
                                value = rule.value,
                                artifact = artifact.path,
                                evidence = redact(line)
                            )
                        )
                        if (matches.size >= MAX_MATCHES) break
                    }
                    if (matches.size >= MAX_MATCHES) break
                }
                if (matches.size >= MAX_MATCHES) break
            }
        }
        val distinct = matches.distinctBy {
            it.indicatorId + "|" + it.artifact + "|" + it.evidence
        }
        return IocScanResult(
            matches = distinct.sortedWith(
                compareByDescending<IocMatch> { it.severity.rank }.thenBy { it.artifact }
            ),
            skippedPatterns = bundle.skippedPatterns,
            scannedArtifacts = artifacts.size,
            warnings = warnings.distinct()
        )
    }

    private fun matchesRule(rule: IocRule, path: String, line: String): Boolean {
        val normalizedLine = line.lowercase()
        val value = rule.value.lowercase()
        return when (rule.objectType) {
            "android-package" -> path == "packages.json" &&
                (normalizedLine.contains("\"package_name\":\"$value\"") ||
                    normalizedLine.contains("\"package_name\": \"$value\""))
            "android-property" -> path.startsWith("settings_") &&
                normalizedLine.contains(value)
            "file" -> (path == "files.json" || path == "files.jsonl" ||
                path.startsWith("files/")) && normalizedLine.contains(value)
            "process" -> path == "processes.txt" && normalizedLine.contains(value)
            "domain-name", "url", "ipv4-addr", "email-addr" ->
                normalizedLine.contains(value)
            else -> false
        }
    }

    private fun redact(line: String): String {
        var value = line.replace('\n', ' ').replace('\r', ' ').trim()
        for (key in sensitiveKeys) {
            val index = value.lowercase().indexOf(key)
            if (index < 0) continue
            val separator = value.indexOf('=', index)
            if (separator < 0) continue
            val end = value.indexOfAny(charArrayOf('&', ';', ' ', '\t'), separator + 1)
            value = if (end < 0) {
                value.substring(0, separator + 1) + "[REDACTED]"
            } else {
                value.substring(0, separator + 1) + "[REDACTED]" + value.substring(end)
            }
        }
        return value.take(MAX_EVIDENCE)
    }

    private const val MAX_LINES = 200_000
    private const val MAX_LINE = 8_000
}
