package com.ecrew.toolkit.apk

import org.w3c.dom.Document
import org.w3c.dom.Element
import org.w3c.dom.Node
import java.io.IOException
import java.io.StringReader
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.ParserConfigurationException
import org.xml.sax.InputSource
import org.xml.sax.SAXException

/** A manifest that could not be parsed or does not have the expected shape. */
class ManifestFactsException(message: String, cause: Throwable? = null) :
    Exception(message, cause)

enum class ComponentKind(val tag: String) {
    ACTIVITY("activity"),
    SERVICE("service"),
    RECEIVER("receiver"),
    PROVIDER("provider")
}

enum class ExportKind {
    EXPLICIT_EXPORTED,
    EXPLICIT_NOT_EXPORTED,
    IMPLICIT_EXPORTED,
    DEFAULT_NOT_EXPORTED
}

data class IntentFilterFacts(
    val actions: List<String>,
    val categories: List<String>,
    val schemes: List<String>,
    val hosts: List<String>,
    val mimeTypes: List<String>
)

data class ComponentFacts(
    val kind: ComponentKind,
    val name: String,
    val label: String?,
    val exported: Boolean,
    val exportKind: ExportKind,
    val permission: String?,
    val intentFilters: List<IntentFilterFacts>,
    val authorities: List<String>,
    val grantUriPermissions: Boolean,
    val readPermission: String?,
    val writePermission: String?,
    val enabled: Boolean,
    val process: String?
) {
    val hasIntentFilter: Boolean
        get() = intentFilters.isNotEmpty()
}

data class DeclaredPermissionFacts(
    val name: String,
    val protectionLevel: String,
    val protectionLabel: String
)

data class FeatureFacts(val name: String, val required: Boolean)

data class ApplicationFacts(
    val label: String?,
    val iconId: Int?,
    val themeId: Int?,
    val debuggable: Boolean?,
    val allowBackup: Boolean?,
    val usesCleartextTraffic: Boolean?,
    val networkSecurityConfigId: Int?,
    val testOnly: Boolean?,
    val enabled: Boolean,
    val permission: String?
)

data class ApkManifestFacts(
    val packageName: String,
    val versionCode: Long,
    val versionName: String?,
    val minSdk: Int?,
    val targetSdk: Int?,
    val compileSdk: Int?,
    val application: ApplicationFacts,
    val permissions: List<String>,
    val declaredPermissions: List<DeclaredPermissionFacts>,
    val features: List<FeatureFacts>,
    val components: List<ComponentFacts>
) {
    val effectiveTargetSdk: Int
        get() = targetSdk ?: minSdk ?: 26

    val activities: List<ComponentFacts>
        get() = components.filter { it.kind == ComponentKind.ACTIVITY }

    val services: List<ComponentFacts>
        get() = components.filter { it.kind == ComponentKind.SERVICE }

    val receivers: List<ComponentFacts>
        get() = components.filter { it.kind == ComponentKind.RECEIVER }

    val providers: List<ComponentFacts>
        get() = components.filter { it.kind == ComponentKind.PROVIDER }
}

/**
 * Turns decoded manifest XML into typed facts. Export defaults follow the platform rules:
 * activities/services/receivers with an intent filter are implicitly exported when
 * android:exported is absent; providers default to not exported for targetSdk 17+.
 */
object ManifestFacts {
    private const val ANDROID_NS = "http://schemas.android.com/apk/res/android"

    fun parse(xml: String, resources: ArscDecoder? = null): ApkManifestFacts {
        val document = parseXml(xml)
        val manifest = document.documentElement
            ?: throw ManifestFactsException("manifest has no root element")
        if (manifest.tagName != "manifest") {
            throw ManifestFactsException("root element is ${manifest.tagName}, not manifest")
        }
        val packageName = manifest.getAttribute("package").trim()
        if (packageName.isEmpty()) {
            throw ManifestFactsException("manifest has no package name")
        }
        val minSdk = intAttr(usesSdk(manifest), "minSdkVersion")
        val targetSdk = intAttr(usesSdk(manifest), "targetSdkVersion")
        val compileSdk = intAttr(manifest, "compileSdkVersion")
        val effectiveTarget = targetSdk ?: minSdk ?: 26
        val applicationElement = children(manifest, "application").firstOrNull()
            ?: throw ManifestFactsException("manifest has no application element")
        val applicationPermission = attr(applicationElement, "permission")
        val applicationEnabled = booleanAttr(applicationElement, "enabled") ?: true
        val application = ApplicationFacts(
            label = resolveLabel(applicationElement, resources),
            iconId = resourceIdAttr(applicationElement, "icon"),
            themeId = resourceIdAttr(applicationElement, "theme"),
            debuggable = booleanAttr(applicationElement, "debuggable"),
            allowBackup = booleanAttr(applicationElement, "allowBackup"),
            usesCleartextTraffic = booleanAttr(applicationElement, "usesCleartextTraffic"),
            networkSecurityConfigId = resourceIdAttr(applicationElement, "networkSecurityConfig"),
            testOnly = booleanAttr(applicationElement, "testOnly"),
            enabled = applicationEnabled,
            permission = applicationPermission
        )
        val permissions = ArrayList<String>()
        for (tag in listOf("uses-permission", "uses-permission-sdk-23")) {
            for (element in children(manifest, tag)) {
                val name = attr(element, "name")
                if (!name.isNullOrEmpty() && !permissions.contains(name)) {
                    permissions.add(name)
                }
            }
        }
        val declaredPermissions = children(manifest, "permission").mapNotNull { element ->
            val name = attr(element, "name") ?: return@mapNotNull null
            val level = attr(element, "protectionLevel") ?: "0x00000000"
            DeclaredPermissionFacts(
                name = name,
                protectionLevel = level,
                protectionLabel = protectionLabel(level)
            )
        }
        val features = children(manifest, "uses-feature").mapNotNull { element ->
            val name = attr(element, "name") ?: return@mapNotNull null
            FeatureFacts(
                name = name,
                required = booleanAttr(element, "required") ?: true
            )
        }
        val components = ArrayList<ComponentFacts>()
        for (element in directChildren(applicationElement)) {
            val kind = ComponentKind.values().firstOrNull { it.tag == element.tagName }
                ?: continue
            val rawName = attr(element, "name")
            if (rawName.isNullOrEmpty()) {
                throw ManifestFactsException("${kind.tag} has no android:name")
            }
            val filters = children(element, "intent-filter").map { filter ->
                parseIntentFilter(filter)
            }
            val explicitExported = booleanAttr(element, "exported")
            val exportKind = exportKind(kind, explicitExported, filters, effectiveTarget)
            val enabled = booleanAttr(element, "enabled") ?: true
            components.add(
                ComponentFacts(
                    kind = kind,
                    name = resolveClassName(packageName, rawName),
                    label = resolveLabel(element, resources),
                    exported = exportKind == ExportKind.EXPLICIT_EXPORTED ||
                        exportKind == ExportKind.IMPLICIT_EXPORTED,
                    exportKind = exportKind,
                    permission = attr(element, "permission"),
                    intentFilters = filters,
                    authorities = (attr(element, "authorities") ?: "")
                        .split(';')
                        .map { it.trim() }
                        .filter { it.isNotEmpty() },
                    grantUriPermissions = booleanAttr(element, "grantUriPermissions") ?: false,
                    readPermission = attr(element, "readPermission"),
                    writePermission = attr(element, "writePermission"),
                    enabled = enabled,
                    process = attr(element, "process")
                )
            )
        }
        return ApkManifestFacts(
            packageName = packageName,
            versionCode = parseVersionCode(attr(manifest, "versionCode")),
            versionName = attr(manifest, "versionName"),
            minSdk = minSdk,
            targetSdk = targetSdk,
            compileSdk = compileSdk,
            application = application,
            permissions = permissions,
            declaredPermissions = declaredPermissions,
            features = features,
            components = components
        )
    }

    private fun exportKind(
        kind: ComponentKind,
        explicit: Boolean?,
        filters: List<IntentFilterFacts>,
        effectiveTarget: Int
    ): ExportKind {
        if (explicit != null) {
            return if (explicit) ExportKind.EXPLICIT_EXPORTED else ExportKind.EXPLICIT_NOT_EXPORTED
        }
        if (kind == ComponentKind.PROVIDER) {
            return if (effectiveTarget <= 16) {
                ExportKind.IMPLICIT_EXPORTED
            } else {
                ExportKind.DEFAULT_NOT_EXPORTED
            }
        }
        return if (filters.isNotEmpty()) {
            ExportKind.IMPLICIT_EXPORTED
        } else {
            ExportKind.DEFAULT_NOT_EXPORTED
        }
    }

    private fun parseIntentFilter(element: Element): IntentFilterFacts {
        val actions = children(element, "action").mapNotNull { attr(it, "name") }.distinct()
        val categories = children(element, "category").mapNotNull { attr(it, "name") }.distinct()
        val data = children(element, "data")
        return IntentFilterFacts(
            actions = actions,
            categories = categories,
            schemes = data.mapNotNull { attr(it, "scheme") }.distinct(),
            hosts = data.mapNotNull { attr(it, "host") }.distinct(),
            mimeTypes = data.mapNotNull { attr(it, "mimeType") }.distinct()
        )
    }

    private fun parseXml(xml: String): Document {
        val factory = DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = true
        factory.isExpandEntityReferences = false
        setFeature(factory, "http://apache.org/xml/features/disallow-doctype-decl", true)
        setFeature(factory, "http://xml.org/sax/features/external-general-entities", false)
        setFeature(factory, "http://xml.org/sax/features/external-parameter-entities", false)
        setFeature(
            factory,
            "http://apache.org/xml/features/nonvalidating/load-external-dtd",
            false
        )
        try {
            factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "")
        } catch (_: IllegalArgumentException) {
        }
        try {
            factory.setAttribute(
                "http://javax.xml.XMLConstants/property/accessExternalSchema",
                ""
            )
        } catch (_: IllegalArgumentException) {
        }
        return try {
            factory.newDocumentBuilder().parse(InputSource(StringReader(xml)))
        } catch (error: SAXException) {
            throw ManifestFactsException("manifest XML is malformed: ${error.message}", error)
        } catch (error: IOException) {
            throw ManifestFactsException("cannot read manifest XML: ${error.message}", error)
        } catch (error: ParserConfigurationException) {
            throw ManifestFactsException("cannot configure manifest parser: ${error.message}", error)
        }
    }

    private fun setFeature(factory: DocumentBuilderFactory, feature: String, value: Boolean) {
        try {
            factory.setFeature(feature, value)
        } catch (_: ParserConfigurationException) {
            // Android's parser may not expose every JAXP feature; DTDs stay disabled where
            // supported and the input is already a decoded manifest, not arbitrary HTML.
        }
    }

    private fun usesSdk(manifest: Element): Element? =
        children(manifest, "uses-sdk").firstOrNull()

    private fun intAttr(element: Element?, name: String): Int? {
        if (element == null) return null
        val value = attr(element, name) ?: return null
        return parseInt(value)
    }

    private fun resourceIdAttr(element: Element, name: String): Int? {
        val value = attr(element, name) ?: return null
        return parseResourceId(value)
    }

    private fun resolveLabel(element: Element, resources: ArscDecoder?): String? {
        val value = attr(element, "label") ?: return null
        val id = parseResourceId(value)
        if (id != null && resources != null) {
            val resolved = resources.resolve(id)
            if (resolved != null && resolved.value.isNotEmpty()) return resolved.value
        }
        return value
    }

    private fun parseVersionCode(value: String?): Long {
        if (value.isNullOrEmpty()) return 0L
        return value.toLongOrNull()
            ?: if (value.startsWith("0x", ignoreCase = true)) {
                value.substring(2).toLongOrNull(16) ?: 0L
            } else {
                0L
            }
    }

    private fun parseInt(value: String): Int? {
        val trimmed = value.trim()
        return trimmed.toIntOrNull()
            ?: if (trimmed.startsWith("0x", ignoreCase = true)) {
                trimmed.substring(2).toIntOrNull(16)
            } else {
                null
            }
    }

    fun parseResourceId(value: String): Int? {
        if (!value.startsWith("@0x", ignoreCase = true)) return null
        val hex = value.substring(3)
        if (hex.isEmpty()) return null
        return try {
            hex.toLong(16).toInt()
        } catch (_: NumberFormatException) {
            null
        }
    }

    private fun protectionLabel(value: String): String {
        val number = parseInt(value) ?: return value
        val base = when (number and 0xF) {
            0 -> "normal"
            1 -> "dangerous"
            2 -> "signature"
            3 -> "signatureOrSystem"
            else -> "unknown"
        }
        val flags = ArrayList<String>()
        if ((number and 0x10) != 0) flags.add("privileged")
        if ((number and 0x20) != 0) flags.add("development")
        if ((number and 0x40) != 0) flags.add("appop")
        if ((number and 0x80) != 0) flags.add("pre23")
        if ((number and 0x100) != 0) flags.add("installer")
        if ((number and 0x200) != 0) flags.add("verifier")
        if ((number and 0x400) != 0) flags.add("preinstalled")
        if ((number and 0x800) != 0) flags.add("setup")
        if ((number and 0x1000) != 0) flags.add("instant")
        if ((number and 0x2000) != 0) flags.add("runtime")
        return if (flags.isEmpty()) base else "$base|" + flags.joinToString("|")
    }

    private fun resolveClassName(packageName: String, rawName: String): String = when {
        rawName.startsWith(".") -> packageName + rawName
        !rawName.contains('.') -> "$packageName.$rawName"
        else -> rawName
    }

    private fun attr(element: Element, name: String): String? = when {
        element.hasAttributeNS(ANDROID_NS, name) -> element.getAttributeNS(ANDROID_NS, name)
        element.hasAttribute(name) -> element.getAttribute(name)
        else -> null
    }

    private fun booleanAttr(element: Element, name: String): Boolean? {
        return when (attr(element, name)?.trim()?.lowercase()) {
            "true" -> true
            "false" -> false
            else -> null
        }
    }

    private fun children(element: Element, name: String): List<Element> =
        directChildren(element).filter { it.tagName == name }

    private fun directChildren(element: Element): List<Element> {
        val result = ArrayList<Element>()
        val nodes = element.childNodes
        for (index in 0 until nodes.length) {
            val node = nodes.item(index)
            if (node.nodeType == Node.ELEMENT_NODE) {
                result.add(node as Element)
            }
        }
        return result
    }
}
