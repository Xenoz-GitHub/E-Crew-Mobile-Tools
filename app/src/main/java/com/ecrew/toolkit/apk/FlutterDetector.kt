package com.ecrew.toolkit.apk

data class FlutterBridge(
    val id: String,
    val title: String,
    val severity: Severity,
    val evidence: String
)

data class FlutterFacts(
    val present: Boolean,
    val enginePath: String?,
    val appPath: String?,
    val dartStrings: List<String>,
    val bridges: List<FlutterBridge>,
    val truncated: Boolean,
    val error: String?
)

data class FlutterLimits(
    val maxAppBytes: Int = 64 * 1024 * 1024,
    val maxStrings: Int = 20_000,
    val maxStringLength: Int = 4096,
    val maxTotalChars: Int = 2_000_000
)

/**
 * Detects Flutter from libflutter.so/libapp.so and reports Dart package/bridge markers.
 * Only libapp.so is read for strings; the engine library is used for presence/path.
 */
class FlutterDetector(private val limits: FlutterLimits = FlutterLimits()) {
    init {
        require(limits.maxAppBytes > 0) { "maxAppBytes must be positive" }
        require(limits.maxStrings > 0) { "maxStrings must be positive" }
        require(limits.maxStringLength >= 4) { "maxStringLength must be at least 4" }
        require(limits.maxTotalChars > 0) { "maxTotalChars must be positive" }
    }

    fun detect(archive: ApkArchive): FlutterFacts {
        val names = archive.entries.map { it.name }
        val engine = names.filter { it.endsWith("/libflutter.so") || it == "libflutter.so" }
            .sorted()
            .firstOrNull()
        val app = names.filter { it.endsWith("/libapp.so") || it == "libapp.so" }
            .sorted()
            .firstOrNull()
        if (engine == null && app == null) {
            return FlutterFacts(
                present = false,
                enginePath = null,
                appPath = null,
                dartStrings = emptyList(),
                bridges = emptyList(),
                truncated = false,
                error = null
            )
        }
        if (app == null) {
            return FlutterFacts(
                present = true,
                enginePath = engine,
                appPath = null,
                dartStrings = emptyList(),
                bridges = emptyList(),
                truncated = false,
                error = null
            )
        }
        return try {
            archive.openEntry(app).use { input ->
                val strings = PrintableStringsReader.read(
                    input = input,
                    maxBytes = limits.maxAppBytes,
                    maxStrings = limits.maxStrings,
                    maxStringLength = limits.maxStringLength,
                    maxTotalChars = limits.maxTotalChars
                )
                FlutterFacts(
                    present = true,
                    enginePath = engine,
                    appPath = app,
                    dartStrings = strings.strings,
                    bridges = findBridges(strings.strings),
                    truncated = strings.truncated,
                    error = null
                )
            }
        } catch (error: Exception) {
            FlutterFacts(
                present = true,
                enginePath = engine,
                appPath = app,
                dartStrings = emptyList(),
                bridges = emptyList(),
                truncated = false,
                error = error.message ?: error.javaClass.simpleName
            )
        }
    }

    fun detectFromStrings(
        enginePath: String?,
        appPath: String?,
        strings: List<String>,
        truncated: Boolean = false
    ): FlutterFacts = FlutterFacts(
        present = enginePath != null || appPath != null,
        enginePath = enginePath,
        appPath = appPath,
        dartStrings = strings,
        bridges = findBridges(strings),
        truncated = truncated,
        error = null
    )

    private fun findBridges(strings: List<String>): List<FlutterBridge> {
        val result = ArrayList<FlutterBridge>()
        for (rule in RULES) {
            val match = strings.firstOrNull { value ->
                val lower = value.lowercase()
                rule.markers.any { marker -> lower.contains(marker) }
            } ?: continue
            result.add(
                FlutterBridge(
                    id = rule.id,
                    title = rule.title,
                    severity = rule.severity,
                    evidence = match.take(160)
                )
            )
        }
        return result
    }

    private data class BridgeRule(
        val id: String,
        val title: String,
        val severity: Severity,
        val markers: List<String>
    )

    private companion object {
        private val RULES = listOf(
            BridgeRule(
                "crypto",
                "Dart cryptography package",
                Severity.INFO,
                listOf("package:crypto/", "package:pointycastle/", "crypto.dart")
            ),
            BridgeRule(
                "dio",
                "Dart dio HTTP client",
                Severity.INFO,
                listOf("package:dio/")
            ),
            BridgeRule(
                "secure_storage",
                "flutter_secure_storage",
                Severity.INFO,
                listOf("flutter_secure_storage")
            ),
            BridgeRule(
                "http",
                "Dart http package",
                Severity.INFO,
                listOf("package:http/")
            ),
            BridgeRule(
                "webview",
                "WebView bridge",
                Severity.MEDIUM,
                listOf("webview_flutter", "platformwebview", "android.webkit.webview")
            ),
            BridgeRule(
                "ffi",
                "Dart FFI bridge",
                Severity.MEDIUM,
                listOf("dart:ffi", "dynamiclibrary")
            ),
            BridgeRule(
                "method_channel",
                "Flutter MethodChannel",
                Severity.LOW,
                listOf("methodchannel")
            ),
            BridgeRule(
                "isolate",
                "Dart isolate",
                Severity.INFO,
                listOf("dart:isolate")
            )
        )
    }
}
