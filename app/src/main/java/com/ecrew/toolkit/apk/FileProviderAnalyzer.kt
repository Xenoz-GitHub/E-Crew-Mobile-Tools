package com.ecrew.toolkit.apk

import org.w3c.dom.Element
import org.xml.sax.InputSource
import java.io.StringReader
import javax.xml.parsers.DocumentBuilderFactory

data class FilePathRule(
    val type: String,
    val name: String,
    val path: String,
    val severity: Severity
)

data class FileProviderConfig(
    val resourceName: String,
    val rules: List<FilePathRule>
) {
    val severity: Severity
        get() = rules.maxByOrNull { it.severity.rank }?.severity ?: Severity.INFO
}

data class FileProviderScan(
    val configs: List<FileProviderConfig>,
    val errors: List<String>,
    val truncated: Boolean
)

/**
 * Reads every XML file under res/xml and classifies FileProvider `<paths>` rules. The APK
 * manifest meta-data association is reported by resource path; it is not claimed that a config
 * is reachable unless the manifest declares a provider that points at it.
 */
object FileProviderAnalyzer {
    private const val MAX_XML_FILES = 200
    private const val MAX_RULES = 2_000

    fun scan(archive: ApkArchive): FileProviderScan {
        val configs = ArrayList<FileProviderConfig>()
        val errors = ArrayList<String>()
        var truncated = false
        val names = archive.entries.map { it.name }
            .filter { it.startsWith("res/xml/") && it.endsWith(".xml") }
            .sorted()
        if (names.size > MAX_XML_FILES) truncated = true
        for (name in names.take(MAX_XML_FILES)) {
            try {
                val xml = AxmlParser.parse(archive.openEntry(name))
                val rules = parseRules(xml)
                if (rules.isNotEmpty()) configs.add(FileProviderConfig(name, rules))
                if (rules.size > MAX_RULES) truncated = true
            } catch (error: Exception) {
                errors.add("$name: ${error.message ?: error.javaClass.simpleName}")
            }
        }
        return FileProviderScan(configs, errors, truncated)
    }

    fun parseRules(xml: String): List<FilePathRule> {
        val factory = DocumentBuilderFactory.newInstance()
        bestEffort(factory, "http://apache.org/xml/features/disallow-doctype-decl", true)
        bestEffort(factory, "http://xml.org/sax/features/external-general-entities", false)
        bestEffort(factory, "http://xml.org/sax/features/external-parameter-entities", false)
        bestEffort(factory, "http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
        val builder = factory.newDocumentBuilder()
        val document = builder.parse(InputSource(StringReader(xml)))
        val root = document.documentElement ?: return emptyList()
        if (root.tagName != "paths") return emptyList()
        val rules = ArrayList<FilePathRule>()
        val children = root.childNodes
        for (index in 0 until children.length) {
            val element = children.item(index) as? Element ?: continue
            val type = element.tagName
            if (type !in TYPES) continue
            val name = element.getAttribute("name").ifBlank { "unnamed" }
            val path = element.getAttribute("path")
            rules.add(FilePathRule(type, name, path, severity(type, path)))
            if (rules.size >= MAX_RULES) break
        }
        return rules
    }

    private fun severity(type: String, path: String): Severity {
        val empty = path.isBlank() || path == "/"
        return when (type) {
            "root-path" -> if (empty) Severity.CRITICAL else Severity.HIGH
            "external-path" -> if (empty) Severity.HIGH else Severity.MEDIUM
            "external-media-path" -> if (empty) Severity.MEDIUM else Severity.LOW
            "cache-path" -> Severity.MEDIUM
            "external-cache-path" -> Severity.MEDIUM
            "files-path" -> Severity.LOW
            "external-files-path" -> Severity.LOW
            else -> Severity.INFO
        }
    }

    private fun bestEffort(factory: DocumentBuilderFactory, feature: String, value: Boolean) {
        try {
            factory.setFeature(feature, value)
        } catch (_: Exception) {
            // Android's parser may not expose every JAXP feature; best effort only.
        }
    }

    private val TYPES = setOf(
        "root-path",
        "files-path",
        "cache-path",
        "external-path",
        "external-files-path",
        "external-cache-path",
        "external-media-path"
    )
}
