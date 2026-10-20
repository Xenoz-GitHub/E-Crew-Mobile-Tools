package com.ecrew.toolkit.util

/** Indicators of compromise extracted from a payload. */
data class IocSet(
    val urls: List<String> = emptyList(),
    val domains: List<String> = emptyList(),
    val ips: List<String> = emptyList(),
    val emails: List<String> = emptyList(),
    val md5: List<String> = emptyList(),
    val sha1: List<String> = emptyList(),
    val sha256: List<String> = emptyList(),
    val credentials: List<String> = emptyList()
) {
    fun totalSize(): Int =
        urls.size + domains.size + ips.size + emails.size +
            md5.size + sha1.size + sha256.size + credentials.size
}

/**
 * Local, regex-based indicator extraction. No network lookups — everything is
 * matched offline against bundled TLD knowledge.
 */
object IocExtractor {

    private val URL_RE = Regex("(?i)\\bhttps?://[^\\s\"'<>\\)]+")
    private val IPV4_RE =
        Regex("\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b")
    private val EMAIL_RE = Regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")
    private val SHA256_RE = Regex("\\b[A-Fa-f0-9]{64}\\b")
    private val SHA1_RE = Regex("\\b[A-Fa-f0-9]{40}\\b")
    private val MD5_RE = Regex("\\b[A-Fa-f0-9]{32}\\b")
    private val CRED_RE = Regex(
        "(?i)\\b(pass(word|wd)?|pwd|token|secret|api[_-]?key|auth|session|sid|login)\\s*[=:]\\s*([^\\s&;,\"'<>]{3,})"
    )
    private val DOMAIN_RE = Regex("\\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,24})\\b")

    /** Common multi-label TLDs that would otherwise produce junk domains. */
    private val KNOWN_TLDS = setOf(
        "com", "net", "org", "io", "co", "ru", "cn", "de", "uk", "us", "info", "biz",
        "top", "xyz", "online", "site", "club", "tech", "app", "dev", "cloud", "me",
        "eu", "in", "jp", "br", "au", "fr", "nl", "it", "kr", "pl", "ca", "ch", "se",
        "no", "es", "pt", "gr", "tr", "ua", "by", "kz", "vn", "th", "id", "ph", "my",
        "sg", "hk", "tw", "edu", "gov", "mil", "int", "name", "mobi", "pro", "tv",
        "cc", "ws", "su", "xyz", "click", "link", "zip", "mov", "sh", "py", "rs",
        "ie", "dk", "fi", "cz", "ro", "hu", "ar", "cl", "mx", "ng", "za", "il"
    )

    fun extract(text: String): IocSet {
        val urls = distinctMatches(URL_RE, text) { it.trimEnd('.', ',', ';', ':', '!', '?') }

        val urlHosts = urls.mapNotNull { hostOf(it) }

        val domains = (urlHosts + DOMAIN_RE.findAll(text).map { it.groupValues[1].lowercase() }
            .filter { candidate ->
                val tld = candidate.substringAfterLast('.')
                tld in KNOWN_TLDS && candidate.count { it == '.' } >= 1
            }).distinct()

        val ips = distinctMatches(IPV4_RE, text)
        val emails = distinctMatches(EMAIL_RE, text)
        val sha256 = distinctMatches(SHA256_RE, text) { it.lowercase() }
        val sha1 = distinctMatches(SHA1_RE, text) { it.lowercase() }
        val md5 = distinctMatches(MD5_RE, text) { it.lowercase() }
        val credentials = distinctMatches(CRED_RE, text)

        return IocSet(
            urls = urls,
            domains = domains,
            ips = ips,
            emails = emails,
            md5 = md5,
            sha1 = sha1,
            sha256 = sha256,
            credentials = credentials
        )
    }

    fun extractUrls(text: String): List<String> =
        distinctMatches(URL_RE, text) { it.trimEnd('.', ',', ';', ':', '!', '?') }

    fun hostOf(url: String): String? = PayloadParser.parseUrl(url)?.host

    private fun distinctMatches(
        re: Regex,
        text: String,
        transform: (String) -> String = { it }
    ): List<String> =
        re.findAll(text).map { transform(it.value) }.filter { it.isNotBlank() }.distinct().toList()
}

