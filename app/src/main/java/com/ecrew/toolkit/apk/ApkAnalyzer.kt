package com.ecrew.toolkit.apk

import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.Locale

data class DexFileFacts(
    val name: String,
    val stringCount: Int,
    val classCount: Int,
    val classes: List<DexClass>
)

data class ApkAnalysis(
    val file: File,
    val sizeBytes: Long,
    val sha256: String,
    val manifest: ApkManifestFacts?,
    val signing: ApkSigningInfo?,
    val dexFiles: List<DexFileFacts>,
    val secrets: SecretScanResult,
    val native: NativeScanResult,
    val flutter: FlutterFacts,
    val fileProviders: FileProviderScan,
    val findings: List<Finding>,
    val errors: List<String>,
    val truncated: Boolean
)

/**
 * Coordinates one APK analysis pass. Parsers stream one entry at a time; DEX files are held
 * only long enough to scan their strings and copy class metadata into the result. Signing is
 * supplied by the Android caller because installed/APK certificate lookup uses PackageManager.
 */
class ApkAnalyzer(
    private val secretScanner: SecretScanner = SecretScanner(),
    private val nativeScanner: NativeScanner = NativeScanner(),
    private val flutterDetector: FlutterDetector = FlutterDetector(),
    private val maxDexFiles: Int = 64
) {
    init {
        require(maxDexFiles > 0) { "maxDexFiles must be positive" }
    }

    fun analyze(file: File, signing: ApkSigningInfo? = null): ApkAnalysis {
        val errors = ArrayList<String>()
        var truncated = false
        val archive = ApkArchive.open(file)
        val manifest: ApkManifestFacts?
        val dexFiles = ArrayList<DexFileFacts>()
        val secretResults = ArrayList<SecretScanResult>()
        val native: NativeScanResult
        val flutter: FlutterFacts
        val fileProviders: FileProviderScan
        archive.use {
            val manifestXml = try {
                AxmlParser.parse(it.openEntry("AndroidManifest.xml"))
            } catch (error: Exception) {
                errors.add("manifest: ${message(error)}")
                null
            }
            val resources = if (it.contains("resources.arsc")) {
                try {
                    ArscDecoder.parse(it.openEntry("resources.arsc"))
                } catch (error: Exception) {
                    errors.add("resources: ${message(error)}")
                    null
                }
            } else {
                null
            }
            manifest = if (manifestXml == null) {
                null
            } else {
                try {
                    ManifestFacts.parse(manifestXml, resources)
                } catch (error: Exception) {
                    errors.add("manifest facts: ${message(error)}")
                    null
                }
            }
            val dexNames = it.entries.map { entry -> entry.name }
                .filter { name -> name.startsWith("classes") && name.endsWith(".dex") }
                .sorted()
            if (dexNames.size > maxDexFiles) {
                truncated = true
                errors.add("only the first $maxDexFiles DEX files were scanned")
            }
            for (name in dexNames.take(maxDexFiles)) {
                try {
                    val parser = DexParser.parse(it.openEntry(name), label = name)
                    secretResults.add(secretScanner.scan(parser.strings, name))
                    if (secretResults.last().truncated) truncated = true
                    dexFiles.add(
                        DexFileFacts(
                            name = name,
                            stringCount = parser.strings.size,
                            classCount = parser.classes.size,
                            classes = parser.classes
                        )
                    )
                } catch (error: Exception) {
                    errors.add("$name: ${message(error)}")
                }
            }
            native = nativeScanner.scanArchive(it)
            flutter = flutterDetector.detect(it)
            fileProviders = FileProviderAnalyzer.scan(it)
            if (native.truncated || flutter.truncated || fileProviders.truncated) truncated = true
            errors.addAll(fileProviders.errors.map { "file provider: $it" })
            for (library in native.libraries) {
                if (library.error != null) {
                    errors.add("${library.path}: ${library.error}")
                }
            }
            if (flutter.error != null) {
                errors.add("flutter: ${flutter.error}")
            }
        }
        val secrets = mergeSecrets(secretResults)
        if (secrets.truncated) truncated = true
        val findings = ArrayList<Finding>()
        if (manifest != null) findings.addAll(FindingEngine.fromManifest(manifest))
        findings.addAll(FindingEngine.fromSecrets(secrets))
        findings.addAll(FindingEngine.fromNative(native))
        findings.addAll(FindingEngine.fromFlutter(flutter))
        findings.addAll(FindingEngine.fromFileProviders(fileProviders))
        if (signing != null) findings.addAll(FindingEngine.fromSigning(signing))
        return ApkAnalysis(
            file = file,
            sizeBytes = file.length(),
            sha256 = hashFile(file),
            manifest = manifest,
            signing = signing,
            dexFiles = dexFiles,
            secrets = secrets,
            native = native,
            flutter = flutter,
            fileProviders = fileProviders,
            findings = FindingEngine.merge(findings),
            errors = errors,
            truncated = truncated
        )
    }

    private fun mergeSecrets(results: List<SecretScanResult>): SecretScanResult {
        val matches = LinkedHashMap<String, SecretMatch>()
        val urls = LinkedHashMap<String, UrlFact>()
        var scanned = 0
        var truncated = false
        for (result in results) {
            scanned += result.scannedStrings
            truncated = truncated || result.truncated
            for (match in result.matches) {
                matches[match.ruleId + "|" + match.sha256 + "|" + match.location] = match
            }
            for (url in result.urls) {
                if (!urls.containsKey(url.url)) urls[url.url] = url
            }
        }
        return SecretScanResult(
            matches = matches.values.toList(),
            urls = urls.values.toList(),
            scannedStrings = scanned,
            truncated = truncated
        )
    }

    private fun hashFile(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { input ->
            val buffer = ByteArray(8192)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { byte ->
            String.format(Locale.US, "%02x", byte.toInt() and 0xFF)
        }
    }

    private fun message(error: Exception): String =
        error.message ?: error.javaClass.simpleName
}
