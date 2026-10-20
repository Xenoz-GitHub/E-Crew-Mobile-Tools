package com.ecrew.toolkit.apk

import java.security.MessageDigest
import java.util.Locale

/** Caps for the string/secret scanner. */
data class SecretLimits(
    val maxInputChars: Int = 8 * 1024 * 1024,
    val maxStringChars: Int = 1_048_576,
    val maxMatches: Int = 5_000,
    val maxMatchesPerRule: Int = 1_000,
    val maxUrls: Int = 5_000
)

data class SecretMatch(
    val ruleId: String,
    val kind: String,
    val severity: Severity,
    val redacted: String,
    val sha256: String,
    val location: String,
    val context: String?
)

data class UrlFact(val url: String, val category: String)

data class SecretScanResult(
    val matches: List<SecretMatch>,
    val urls: List<UrlFact>,
    val scannedStrings: Int,
    val truncated: Boolean
)

/**
 * Pure-JVM regex scan for common credential shapes. The full match is hashed and then
 * discarded; results carry only a first-4/last-4 preview, a SHA-256 and a location/context.
 * URLs are sanitized (userinfo, query and fragment removed) and categorized.
 */
class SecretScanner(private val limits: SecretLimits = SecretLimits()) {
    init {
        require(limits.maxInputChars > 0) { "maxInputChars must be positive" }
        require(limits.maxStringChars > 0) { "maxStringChars must be positive" }
        require(limits.maxMatches > 0) { "maxMatches must be positive" }
        require(limits.maxMatchesPerRule > 0) { "maxMatchesPerRule must be positive" }
        require(limits.maxUrls > 0) { "maxUrls must be positive" }
    }

    fun scan(
        strings: Iterable<String>,
        location: String,
        context: String? = null
    ): SecretScanResult {
        val matches = ArrayList<SecretMatch>()
        val urls = ArrayList<UrlFact>()
        val seenMatches = HashSet<String>()
        val seenUrls = HashSet<String>()
        var scanned = 0
        var inputChars = 0L
        var truncated = false

        textLoop@ for (text in strings) {
            if (text.isEmpty()) continue
            if (text.length > limits.maxStringChars) {
                truncated = true
                continue
            }
            if (inputChars + text.length > limits.maxInputChars) {
                truncated = true
                break
            }
            inputChars += text.length
            scanned++
            for (rule in RULES) {
                var ruleMatches = 0
                for (match in rule.pattern.findAll(text)) {
                    val value = match.value
                    if (value.isEmpty()) continue
                    val hash = sha256(value)
                    val key = rule.id + "|" + hash + "|" + location
                    if (!seenMatches.add(key)) continue
                    matches.add(
                        SecretMatch(
                            ruleId = rule.id,
                            kind = rule.kind,
                            severity = rule.severity,
                            redacted = redact(value),
                            sha256 = hash,
                            location = location,
                            context = context
                        )
                    )
                    ruleMatches++
                    if (ruleMatches >= limits.maxMatchesPerRule) {
                        truncated = true
                        break
                    }
                    if (matches.size >= limits.maxMatches) {
                        truncated = true
                        break@textLoop
                    }
                }
            }

            for (match in URL_PATTERN.findAll(text)) {
                if (urls.size >= limits.maxUrls) {
                    truncated = true
                    break@textLoop
                }
                val sanitized = sanitizeUrl(match.value)
                if (sanitized == null || !seenUrls.add(sanitized)) continue
                val category = categorize(sanitized)
                urls.add(UrlFact(sanitized, category))
                val host = hostOf(sanitized)
                if (host.endsWith(".firebaseio.com") || host.endsWith(".firebaseapp.com")) {
                    val added = addDerivedMatch(
                        matches = matches,
                        seen = seenMatches,
                        ruleId = "firebase_url",
                        kind = "Firebase endpoint",
                        severity = Severity.MEDIUM,
                        value = sanitized,
                        location = location,
                        context = context,
                        maxMatches = limits.maxMatches
                    )
                    if (!added) {
                        truncated = true
                        break@textLoop
                    }
                }
                if (isOAuthEndpoint(sanitized)) {
                    val added = addDerivedMatch(
                        matches = matches,
                        seen = seenMatches,
                        ruleId = "oauth_endpoint",
                        kind = "OAuth endpoint",
                        severity = Severity.MEDIUM,
                        value = sanitized,
                        location = location,
                        context = context,
                        maxMatches = limits.maxMatches
                    )
                    if (!added) {
                        truncated = true
                        break@textLoop
                    }
                }
            }
        }
        return SecretScanResult(
            matches = matches,
            urls = urls,
            scannedStrings = scanned,
            truncated = truncated
        )
    }

    fun scanDex(parser: DexParser, location: String = "classes.dex"): SecretScanResult =
        scan(parser.strings, location)

    fun scanText(text: String, location: String = "text"): SecretScanResult =
        scan(listOf(text), location)

    private fun addDerivedMatch(
        matches: MutableList<SecretMatch>,
        seen: MutableSet<String>,
        ruleId: String,
        kind: String,
        severity: Severity,
        value: String,
        location: String,
        context: String?,
        maxMatches: Int
    ): Boolean {
        if (matches.size >= maxMatches) return false
        val hash = sha256(value)
        val key = ruleId + "|" + hash + "|" + location
        if (!seen.add(key)) return true
        matches.add(
            SecretMatch(
                ruleId = ruleId,
                kind = kind,
                severity = severity,
                redacted = redact(value),
                sha256 = hash,
                location = location,
                context = context
            )
        )
        return true
    }

    private fun sanitizeUrl(raw: String): String? {
        var url = raw.trim()
        while (url.isNotEmpty() && url.last() in ".,;:!?)]}\"'") {
            url = url.dropLast(1)
        }
        val schemeEnd = url.indexOf("://")
        if (schemeEnd <= 0) return null
        val query = url.indexOf('?')
        if (query >= 0) url = url.substring(0, query)
        val fragment = url.indexOf('#')
        if (fragment >= 0) url = url.substring(0, fragment)
        val authorityStart = schemeEnd + 3
        val slash = url.indexOf('/', authorityStart)
        val authorityEnd = if (slash >= 0) slash else url.length
        val at = url.lastIndexOf('@', authorityEnd - 1)
        if (at >= authorityStart) {
            url = url.substring(0, authorityStart) + url.substring(at + 1)
        }
        if (url.length <= authorityStart) return null
        return url
    }

    private fun hostOf(url: String): String {
        val schemeEnd = url.indexOf("://")
        val authorityStart = schemeEnd + 3
        val slash = url.indexOf('/', authorityStart)
        val authority = if (slash >= 0) {
            url.substring(authorityStart, slash)
        } else {
            url.substring(authorityStart)
        }
        return authority.substringBefore(':').lowercase(Locale.US)
    }

    private fun categorize(url: String): String {
        val host = hostOf(url)
        val lower = url.lowercase(Locale.US)
        return when {
            host.contains("firebase") || host.contains("google-analytics") ||
                host.contains("analytics") || host.contains("mixpanel") ||
                host.contains("amplitude") || host.contains("segment") ||
                host.contains("sentry") || host.contains("crashlytics") -> "Analytics"

            host.contains("facebook") || host.contains("twitter") ||
                host.contains("linkedin") || host.contains("instagram") ||
                host.contains("tiktok") || host.contains("telegram") ||
                host == "x.com" -> "Social"

            host.contains("webhook") || host.contains("hooks.slack") ||
                (host.contains("discord") && lower.contains("/api/webhooks")) ||
                host.contains("zapier") -> "Webhook"

            host.startsWith("cdn.") || host.contains("cloudfront") ||
                host.contains("akamai") || host.startsWith("static.") ||
                host.contains("jsdelivr") || host.contains("unpkg") -> "CDN"

            host.startsWith("api.") || lower.contains("/api/") ||
                lower.contains("/graphql") -> "API"

            else -> "Other"
        }
    }

    private fun isOAuthEndpoint(url: String): Boolean {
        val lower = url.lowercase(Locale.US)
        return lower.contains("/oauth") || lower.contains("/authorize") ||
            lower.contains("/authorization") || lower.contains("/token")
    }

    private fun redact(value: String): String = when {
        value.length >= 9 -> value.take(4) + "..." + value.takeLast(4)
        value.length >= 5 -> value.take(2) + "..." + value.takeLast(2)
        else -> "***"
    }

    private fun sha256(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
        return digest.joinToString("") { byte ->
            String.format(Locale.US, "%02x", byte.toInt() and 0xFF)
        }
    }

    private data class Rule(
        val id: String,
        val kind: String,
        val severity: Severity,
        val pattern: Regex
    )

    private companion object {
        private val URL_PATTERN = Regex("""https?://[^\s"'<>\\]+""")

        private val RULES = listOf(
            Rule(
                "google_api_key",
                "Google API key",
                Severity.HIGH,
                Regex("""\bAIza[0-9A-Za-z_-]{35}\b""")
            ),
            Rule(
                "aws_access_key",
                "AWS access key",
                Severity.HIGH,
                Regex("""\bAKIA[0-9A-Z]{16}\b""")
            ),
            Rule(
                "stripe_secret_key",
                "Stripe secret key",
                Severity.HIGH,
                Regex("""\bsk_live_[0-9A-Za-z]{24,}\b""")
            ),
            Rule(
                "stripe_publishable_key",
                "Stripe publishable key",
                Severity.LOW,
                Regex("""\bpk_live_[0-9A-Za-z]{24,}\b""")
            ),
            Rule(
                "jwt",
                "JWT",
                Severity.HIGH,
                Regex("""eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{4,}""")
            ),
            Rule(
                "private_key",
                "Private key marker",
                Severity.CRITICAL,
                Regex("""-----BEGIN [A-Z ]*PRIVATE KEY-----""")
            ),
            Rule(
                "certificate",
                "Certificate marker",
                Severity.INFO,
                Regex("""-----BEGIN CERTIFICATE-----""")
            ),
            Rule(
                "bitcoin_address",
                "Bitcoin address",
                Severity.MEDIUM,
                Regex("""\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b""")
            ),
            Rule(
                "ethereum_address",
                "Ethereum address",
                Severity.MEDIUM,
                Regex("""\b0x[a-fA-F0-9]{40}\b""")
            ),
            Rule(
                "email",
                "Email address",
                Severity.LOW,
                Regex("""[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}""")
            )
        )
    }
}
