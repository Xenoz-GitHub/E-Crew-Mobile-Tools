package com.ecrew.toolkit.apk

import java.io.InputStream

data class NativeThreat(
    val ruleId: String,
    val title: String,
    val severity: Severity,
    val libraryPath: String,
    val preview: String
)

data class NativeLibraryFacts(
    val path: String,
    val sizeBytes: Long,
    val sha256: String,
    val isElf: Boolean,
    val is64Bit: Boolean,
    val strings: List<String>,
    val threats: List<NativeThreat>,
    val truncated: Boolean,
    val error: String?
)

data class NativeScanResult(
    val libraries: List<NativeLibraryFacts>,
    val threats: List<NativeThreat>,
    val truncated: Boolean
)

data class NativeLimits(
    val maxLibraries: Int = 256,
    val maxLibraryBytes: Int = 32 * 1024 * 1024,
    val maxStringsPerLibrary: Int = 20_000,
    val maxStringLength: Int = 4096,
    val maxTotalCharsPerLibrary: Int = 2_000_000
)

/**
 * Extracts printable strings and threat markers from native libraries. The APK is never
 * extracted; each lib entry is streamed once, with per-library and per-archive caps.
 */
class NativeScanner(private val limits: NativeLimits = NativeLimits()) {
    init {
        require(limits.maxLibraries > 0) { "maxLibraries must be positive" }
        require(limits.maxLibraryBytes > 0) { "maxLibraryBytes must be positive" }
        require(limits.maxStringsPerLibrary > 0) { "maxStringsPerLibrary must be positive" }
        require(limits.maxStringLength >= 4) { "maxStringLength must be at least 4" }
        require(limits.maxTotalCharsPerLibrary > 0) {
            "maxTotalCharsPerLibrary must be positive"
        }
    }

    fun scan(path: String, input: InputStream): NativeLibraryFacts {
        val strings = PrintableStringsReader.read(
            input = input,
            maxBytes = limits.maxLibraryBytes,
            maxStrings = limits.maxStringsPerLibrary,
            maxStringLength = limits.maxStringLength,
            maxTotalChars = limits.maxTotalCharsPerLibrary
        )
        val threats = findThreats(path, strings.strings)
        return NativeLibraryFacts(
            path = path,
            sizeBytes = strings.bytesRead,
            sha256 = strings.sha256,
            isElf = strings.isElf,
            is64Bit = strings.is64Bit,
            strings = strings.strings,
            threats = threats,
            truncated = strings.truncated,
            error = null
        )
    }

    fun scanArchive(archive: ApkArchive): NativeScanResult {
        val paths = archive.entries
            .map { it.name }
            .filter { it.startsWith("lib/") && it.endsWith(".so") }
            .sorted()
        val libraries = ArrayList<NativeLibraryFacts>()
        var truncated = false
        for (path in paths) {
            if (libraries.size >= limits.maxLibraries) {
                truncated = true
                break
            }
            val facts = try {
                archive.openEntry(path).use { scan(path, it) }
            } catch (error: Exception) {
                NativeLibraryFacts(
                    path = path,
                    sizeBytes = 0,
                    sha256 = "",
                    isElf = false,
                    is64Bit = false,
                    strings = emptyList(),
                    threats = emptyList(),
                    truncated = false,
                    error = error.message ?: error.javaClass.simpleName
                )
            }
            libraries.add(facts)
            if (facts.truncated) truncated = true
        }
        return NativeScanResult(
            libraries = libraries,
            threats = libraries.flatMap { it.threats },
            truncated = truncated
        )
    }

    private fun findThreats(path: String, strings: List<String>): List<NativeThreat> {
        val result = ArrayList<NativeThreat>()
        for (rule in RULES) {
            val match = strings.firstOrNull { value ->
                val lower = value.lowercase()
                rule.markers.any { marker -> lower.contains(marker) }
            } ?: continue
            result.add(
                NativeThreat(
                    ruleId = rule.id,
                    title = rule.title,
                    severity = rule.severity,
                    libraryPath = path,
                    preview = match.take(160)
                )
            )
        }
        return result
    }

    private data class ThreatRule(
        val id: String,
        val title: String,
        val severity: Severity,
        val markers: List<String>
    )

    private companion object {
        private val RULES = listOf(
            ThreatRule(
                "frida",
                "Frida instrumentation markers",
                Severity.HIGH,
                listOf("frida", "gum-js-loop", "linjector")
            ),
            ThreatRule(
                "gdb",
                "GDB server markers",
                Severity.HIGH,
                listOf("gdbserver")
            ),
            ThreatRule(
                "lldb",
                "LLDB server markers",
                Severity.HIGH,
                listOf("lldb-server")
            ),
            ThreatRule(
                "xposed",
                "Xposed framework markers",
                Severity.HIGH,
                listOf("xposed", "de.robv.android.xposed")
            ),
            ThreatRule(
                "magisk",
                "Magisk path markers",
                Severity.MEDIUM,
                listOf("/sbin/magisk", "magisk")
            ),
            ThreatRule(
                "anti_debug",
                "Anti-debug strings",
                Severity.LOW,
                listOf("ptrace", "tracerpid", "isdebuggerpresent")
            ),
            ThreatRule(
                "jni",
                "JNI entry point",
                Severity.INFO,
                listOf("jni_onload")
            ),
            ThreatRule(
                "openssl",
                "OpenSSL banner",
                Severity.INFO,
                listOf("openssl ")
            ),
            ThreatRule(
                "packer",
                "Packer markers",
                Severity.MEDIUM,
                listOf("upx!", "libjiagu", "libprotectclass", "libdexhelper")
            )
        )
    }
}
