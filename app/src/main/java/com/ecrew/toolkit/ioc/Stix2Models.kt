package com.ecrew.toolkit.ioc

import com.ecrew.toolkit.apk.Severity

class IocException(message: String) : Exception(message)

data class IocRule(
    val objectType: String,
    val path: String,
    val value: String
)

data class StixIndicator(
    val id: String,
    val name: String,
    val description: String,
    val severity: Severity,
    val pattern: String,
    val rules: List<IocRule>,
    val skipped: Boolean
)

data class StixBundle(
    val indicators: List<StixIndicator>,
    val skippedPatterns: Int
)

/**
 * Minimal STIX 2.1 bundle reader. Only the indicator object type is consumed. Supported
 * comparator forms are `[object:path = 'value']` joined by OR; everything else increments a
 * visible skipped counter and is never silently treated as a match.
 */
object Stix2Parser {
    private val supportedTypes = setOf(
        "file",
        "domain-name",
        "url",
        "ipv4-addr",
        "email-addr",
        "process",
        "android-package",
        "android-property"
    )
    private val supportedPaths = setOf(
        "path",
        "name",
        "value"
    )
    private val ruleRegex = Regex(
        "\\[([a-z0-9-]+):([a-z0-9_.-]+)\\s*=\\s*'([^']*)'\\]",
        RegexOption.IGNORE_CASE
    )

    fun parse(text: String): StixBundle {
        val root = JsonReader.objectMap(JsonReader.parse(text), "bundle")
        if (root["type"] != "bundle") throw IocException("root object is not a STIX bundle")
        val objects = JsonReader.array(root["objects"], "bundle objects")
        val indicators = ArrayList<StixIndicator>()
        var skippedPatterns = 0
        for (raw in objects) {
            val obj = raw as? Map<*, *> ?: continue
            if (obj["type"] != "indicator") continue
            val id = obj["id"] as? String
                ?: throw IocException("indicator has no id")
            val pattern = obj["pattern"] as? String
                ?: throw IocException("indicator $id has no pattern")
            val name = (obj["name"] as? String)?.takeIf { it.isNotBlank() } ?: id
            val description = (obj["description"] as? String) ?: ""
            val severity = severity(obj["x_ecrew_severity"], obj["labels"])
            val rules = ArrayList<IocRule>()
            var unsupported = false
            val parts = pattern.split(Regex("\\s+OR\\s+", RegexOption.IGNORE_CASE))
            for (part in parts) {
                val match = ruleRegex.matchEntire(part.trim())
                if (match == null) {
                    unsupported = true
                    skippedPatterns++
                    continue
                }
                val objectType = match.groupValues[1].lowercase()
                val path = match.groupValues[2].lowercase()
                val value = match.groupValues[3]
                if (objectType !in supportedTypes || path !in supportedPaths || value.isEmpty()) {
                    unsupported = true
                    skippedPatterns++
                    continue
                }
                rules.add(IocRule(objectType, path, value))
            }
            if (rules.isEmpty()) {
                unsupported = true
            }
            indicators.add(
                StixIndicator(
                    id = id,
                    name = name,
                    description = description,
                    severity = severity,
                    pattern = pattern,
                    rules = rules,
                    skipped = unsupported
                )
            )
        }
        return StixBundle(indicators, skippedPatterns)
    }

    private fun severity(declared: Any?, labels: Any?): Severity {
        val raw = (declared as? String)?.lowercase()
        val fromRaw = raw?.let {
            when (it) {
                "critical" -> Severity.CRITICAL
                "high" -> Severity.HIGH
                "medium" -> Severity.MEDIUM
                "low" -> Severity.LOW
                "info" -> Severity.INFO
                else -> null
            }
        }
        if (fromRaw != null) return fromRaw
        val labelsText = (labels as? List<*>)?.joinToString(" ") { it.toString().lowercase() }
            ?: ""
        return when {
            labelsText.contains("critical") -> Severity.CRITICAL
            labelsText.contains("high") || labelsText.contains("malicious") -> Severity.HIGH
            labelsText.contains("medium") || labelsText.contains("suspicious") -> Severity.MEDIUM
            labelsText.contains("low") -> Severity.LOW
            else -> Severity.MEDIUM
        }
    }
}
