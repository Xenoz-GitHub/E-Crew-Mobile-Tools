package com.ecrew.toolkit.acquisition

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Environment
import android.provider.Settings
import android.database.Cursor
import android.net.Uri
import androidx.core.content.ContextCompat
import com.ecrew.toolkit.forensics.ForensicsKit
import java.io.File
import java.security.MessageDigest

interface QfModule {
    val id: String
    val label: String
    fun collect(sink: ArtifactSink): ModuleOutput
}

data class ModuleOutput(
    val status: ModuleStatus,
    val artifacts: List<String>,
    val error: String?
)

class ArtifactSink(private val writer: AndroidQfWriter) {
    private val names = LinkedHashSet<String>()

    fun text(path: String, value: String): String {
        val name = writer.addText(path, value)
        names.add(name)
        return name
    }

    fun bytes(path: String, value: ByteArray): String {
        val name = writer.add(path, value)
        names.add(name)
        return name
    }

    fun names(): List<String> = names.toList()
}

@Suppress("DEPRECATION")
class PackagesModule(private val context: Context) : QfModule {
    override val id = "packages"
    override val label = "Installed packages"

    override fun collect(sink: ArtifactSink): ModuleOutput {
        val manager = context.packageManager
        val packages = try {
            manager.getInstalledPackages(PackageManager.GET_SIGNATURES)
        } catch (error: Exception) {
            return ModuleOutput(ModuleStatus.FAILED, emptyList(), error.javaClass.simpleName)
        }.sortedBy { it.packageName }
        val builder = StringBuilder("[\n")
        var included = 0
        for (info in packages) {
            if (included >= MAX_PACKAGES) break
            val app = info.applicationInfo ?: continue
            val signatures = info.signatures?.map { signature ->
                sha256(signature.toByteArray())
            } ?: emptyList()
            if (included > 0) builder.append(",\n")
            builder.append("  {")
            builder.append("\"package_name\":").append(QfJson.quote(info.packageName)).append(',')
            builder.append("\"version_name\":").append(QfJson.quote(info.versionName)).append(',')
            builder.append("\"version_code\":").append(info.versionCode).append(',')
            builder.append("\"installer\":").append(QfJson.quote(installer(manager, info.packageName)))
                .append(',')
            builder.append("\"uid\":").append(app.uid).append(',')
            builder.append("\"system\":").append(app.flags and ApplicationInfo.FLAG_SYSTEM != 0)
                .append(',')
            builder.append("\"debuggable\":")
                .append(app.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0).append(',')
            builder.append("\"enabled\":").append(app.enabled).append(',')
            builder.append("\"target_sdk\":").append(app.targetSdkVersion).append(',')
            builder.append("\"min_sdk\":").append(app.minSdkVersion).append(',')
            builder.append("\"first_install_time\":").append(info.firstInstallTime).append(',')
            builder.append("\"last_update_time\":").append(info.lastUpdateTime).append(',')
            builder.append("\"signatures\":[")
            signatures.forEachIndexed { index, value ->
                if (index > 0) builder.append(',')
                builder.append(QfJson.quote(value))
            }
            builder.append("]}")
            included++
        }
        builder.append("\n]\n")
        val artifact = sink.text("packages.json", builder.toString())
        val error = if (packages.size > included) {
            "package cap reached at $MAX_PACKAGES"
        } else {
            null
        }
        return ModuleOutput(
            if (error == null) ModuleStatus.COMPLETED else ModuleStatus.PARTIAL,
            listOf(artifact),
            error
        )
    }

    private fun installer(manager: PackageManager, packageName: String): String? =
        try {
            manager.getInstallerPackageName(packageName)
        } catch (_: Exception) {
            null
        }

    private companion object {
        const val MAX_PACKAGES = 500
    }
}

class SettingsModule(private val context: Context) : QfModule {
    override val id = "settings"
    override val label = "Settings provider"

    override fun collect(sink: ArtifactSink): ModuleOutput {
        val artifacts = ArrayList<String>()
        fun write(name: String, values: Map<String, *>) {
            val text = values.entries
                .filter { it.key.isNotBlank() }
                .sortedBy { it.key }
                .joinToString("\n") { "${it.key}=${it.value ?: ""}" }
            artifacts.add(sink.text(name, text + if (text.isEmpty()) "" else "\n"))
        }
        write("settings_system.txt", readSettings(Settings.System.CONTENT_URI))
        write("settings_secure.txt", readSettings(Settings.Secure.CONTENT_URI))
        write("settings_global.txt", readSettings(Settings.Global.CONTENT_URI))
        return ModuleOutput(ModuleStatus.COMPLETED, artifacts, null)
    }

    private fun readSettings(uri: Uri): Map<String, String> {
        val values = LinkedHashMap<String, String>()
        try {
            context.contentResolver.query(
                uri,
                arrayOf("name", "value"),
                null,
                null,
                "name"
            )?.use { cursor ->
                while (cursor.moveToNext() && values.size < MAX_SETTINGS) {
                    val name = cursor.getStringOrNull(0) ?: continue
                    val value = cursor.getStringOrNull(1) ?: ""
                    values[name] = value
                }
            }
        } catch (_: Exception) {
            // A restricted settings provider yields an empty section, not a crash.
        }
        return values
    }

    private companion object {
        const val MAX_SETTINGS = 5_000
    }
}

class GetpropModule(private val context: Context) : QfModule {
    override val id = "getprop"
    override val label = "System properties"

    override fun collect(sink: ArtifactSink): ModuleOutput {
        val output = QfShell(context).run(listOf("/system/bin/getprop"))
        if (output.exitCode != 0) {
            return ModuleOutput(
                ModuleStatus.PARTIAL,
                emptyList(),
                output.error ?: "getprop exited ${output.exitCode}"
            )
        }
        val artifact = sink.text("getprop.txt", output.text)
        return ModuleOutput(
            if (output.truncated) ModuleStatus.PARTIAL else ModuleStatus.COMPLETED,
            listOf(artifact),
            if (output.truncated) "getprop output truncated" else null
        )
    }
}

@Suppress("DEPRECATION")
class NetworkStateModule(private val context: Context) : QfModule {
    override val id = "network"
    override val label = "Network state"

    override fun collect(sink: ArtifactSink): ModuleOutput {
        val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE)
            as? ConnectivityManager
            ?: return ModuleOutput(ModuleStatus.FAILED, emptyList(), "no connectivity manager")
        val builder = StringBuilder("{\n")
        val active = connectivity.activeNetwork
        val capabilities: NetworkCapabilities? = active?.let {
            try {
                connectivity.getNetworkCapabilities(it)
            } catch (_: Exception) {
                null
            }
        }
        val link: LinkProperties? = active?.let {
            try {
                connectivity.getLinkProperties(it)
            } catch (_: Exception) {
                null
            }
        }
        builder.append("  \"active_network\":")
            .append(if (active == null) "null" else QfJson.quote(active.toString())).append(",\n")
        builder.append("  \"transports\":[")
        if (capabilities != null) {
            val transports = ArrayList<String>()
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                transports.add("wifi")
            }
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                transports.add("cellular")
            }
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) {
                transports.add("bluetooth")
            }
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                transports.add("ethernet")
            }
            transports.forEachIndexed { index, value ->
                if (index > 0) builder.append(',')
                builder.append(QfJson.quote(value))
            }
        }
        builder.append("],\n")
        builder.append("  \"dns\":[")
        link?.dnsServers?.forEachIndexed { index, address ->
            if (index > 0) builder.append(',')
            builder.append(QfJson.quote(address.hostAddress))
        }
        builder.append("],\n")
        builder.append("  \"interface\":")
            .append(QfJson.quote(link?.interfaceName)).append(",\n")
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        val wifiInfo = wifi?.connectionInfo
        builder.append("  \"wifi\":{")
        builder.append("\"ssid\":").append(QfJson.quote(wifiInfo?.ssid)).append(',')
        builder.append("\"bssid\":").append(QfJson.quote(wifiInfo?.bssid)).append(',')
        builder.append("\"rssi\":").append(wifiInfo?.rssi ?: 0)
        builder.append("}\n")
        builder.append("}\n")
        val artifact = sink.text("networks.json", builder.toString())
        return ModuleOutput(ModuleStatus.COMPLETED, listOf(artifact), null)
    }
}

class ContentResolverModule(private val context: Context) : QfModule {
    override val id = "content"
    override val label = "SMS, MMS, calls and contacts"

    override fun collect(sink: ArtifactSink): ModuleOutput {
        val artifacts = ArrayList<String>()
        val errors = ArrayList<String>()
        if (has(Manifest.permission.READ_SMS)) {
            val sms = ForensicsKit.readSms(context)
            artifacts.add(sink.text("content/sms.jsonl", sms.joinToString("\n") { record ->
                "{\"address\":${QfJson.quote(record.address)},\"date\":${record.date}," +
                    "\"direction\":${QfJson.quote(record.direction)}," +
                    "\"body\":${QfJson.quote(record.body)}}"
            } + if (sms.isEmpty()) "" else "\n"))
            val mms = readMms()
            if (mms != null) {
                artifacts.add(sink.text("content/mms.jsonl", mms))
            } else {
                errors.add("MMS provider unavailable")
            }
        } else {
            errors.add("READ_SMS not granted")
        }
        if (has(Manifest.permission.READ_CALL_LOG)) {
            val calls = ForensicsKit.readCalls(context)
            artifacts.add(sink.text("content/calls.jsonl", calls.joinToString("\n") { record ->
                "{\"number\":${QfJson.quote(record.number)},\"name\":${QfJson.quote(record.name)}," +
                    "\"type\":${QfJson.quote(record.type)},\"date\":${record.date}," +
                    "\"duration_seconds\":${record.durationSeconds}}"
            } + if (calls.isEmpty()) "" else "\n"))
        } else {
            errors.add("READ_CALL_LOG not granted")
        }
        if (has(Manifest.permission.READ_CONTACTS)) {
            val contacts = ForensicsKit.readContacts(context)
            artifacts.add(sink.text("content/contacts.jsonl", contacts.joinToString("\n") { record ->
                "{\"name\":${QfJson.quote(record.name)},\"number\":${QfJson.quote(record.number)}," +
                    "\"type\":${QfJson.quote(record.type)}}"
            } + if (contacts.isEmpty()) "" else "\n"))
        } else {
            errors.add("READ_CONTACTS not granted")
        }
        return ModuleOutput(
            if (errors.isEmpty()) ModuleStatus.COMPLETED else ModuleStatus.PARTIAL,
            artifacts,
            errors.joinToString("; ").ifBlank { null }
        )
    }

    private fun readMms(): String? {
        val resolver = context.contentResolver
        val uri = Uri.parse("content://mms")
        val projection = arrayOf("_id", "date", "msg_box", "address")
        return try {
            resolver.query(uri, projection, null, null, "date DESC")?.use { cursor ->
                val builder = StringBuilder()
                var count = 0
                while (cursor.moveToNext() && count < MAX_CONTENT_ROWS) {
                    builder.append("{\"id\":").append(cursor.getLong(0)).append(',')
                    builder.append("\"date\":").append(cursor.getLong(1)).append(',')
                    builder.append("\"box\":").append(cursor.getInt(2)).append(',')
                    builder.append("\"address\":")
                        .append(QfJson.quote(cursor.getStringOrNull(3))).append("}\n")
                    count++
                }
                builder.toString()
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun has(permission: String): Boolean =
        ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED

    private companion object {
        const val MAX_CONTENT_ROWS = 20_000
    }
}

class FilesModule(private val context: Context) : QfModule {
    override val id = "files"
    override val label = "Shared-storage metadata"

    override fun collect(sink: ArtifactSink): ModuleOutput {
        if (ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.READ_EXTERNAL_STORAGE
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            return ModuleOutput(
                ModuleStatus.PARTIAL,
                emptyList(),
                "READ_EXTERNAL_STORAGE not granted"
            )
        }
        val root = Environment.getExternalStorageDirectory()
        val builder = StringBuilder()
        var count = 0
        var truncated = false
        val queue = ArrayDeque<Pair<File, Int>>()
        queue.add(root to 0)
        while (queue.isNotEmpty() && count < MAX_FILES) {
            val (directory, depth) = queue.removeFirst()
            val children = try {
                directory.listFiles()
            } catch (_: Exception) {
                null
            } ?: continue
            for (child in children.sortedBy { it.name }) {
                if (count >= MAX_FILES) {
                    truncated = true
                    break
                }
                if (child.isFile) {
                    builder.append("{\"path\":").append(QfJson.quote(child.absolutePath))
                        .append(",\"size\":").append(child.length())
                        .append(",\"modified\":").append(child.lastModified()).append("}\n")
                    count++
                } else if (child.isDirectory && depth < MAX_DEPTH && !child.name.startsWith(".")) {
                    queue.add(child to depth + 1)
                }
            }
        }
        val artifact = sink.text("files.jsonl", builder.toString())
        return ModuleOutput(
            if (truncated) ModuleStatus.PARTIAL else ModuleStatus.COMPLETED,
            listOf(artifact),
            if (truncated) "file metadata cap reached" else null
        )
    }

    private companion object {
        const val MAX_FILES = 5_000
        const val MAX_DEPTH = 3
    }
}

class ApkCopyModule(private val context: Context) : QfModule {
    override val id = "apks"
    override val label = "User APK copies"

    override fun collect(sink: ArtifactSink): ModuleOutput {
        val manager = context.packageManager
        val packages = try {
            manager.getInstalledPackages(0)
        } catch (error: Exception) {
            return ModuleOutput(ModuleStatus.FAILED, emptyList(), error.javaClass.simpleName)
        }.filter { info ->
            val app = info.applicationInfo
            app != null && app.flags and ApplicationInfo.FLAG_SYSTEM == 0
        }.sortedBy { it.packageName }
        val artifacts = ArrayList<String>()
        var copied = 0
        var bytes = 0L
        var truncated = false
        for (info in packages) {
            if (copied >= MAX_APKS || bytes >= MAX_BYTES) {
                truncated = true
                break
            }
            val app = info.applicationInfo ?: continue
            val source = File(app.sourceDir)
            if (!source.isFile) continue
            if (source.length() > MAX_SINGLE_BYTES) {
                truncated = true
                continue
            }
            try {
                artifacts.add(sink.bytes("apks/${info.packageName}.apk", source.readBytes()))
                copied++
                bytes += source.length()
            } catch (_: Exception) {
                truncated = true
            }
        }
        return ModuleOutput(
            if (truncated) ModuleStatus.PARTIAL else ModuleStatus.COMPLETED,
            artifacts,
            if (truncated) "APK copy cap or unreadable APK" else null
        )
    }

    private companion object {
        const val MAX_APKS = 50
        const val MAX_BYTES = 300L * 1024 * 1024
        const val MAX_SINGLE_BYTES = 64L * 1024 * 1024
    }
}

class PrivilegedModule(private val context: Context) : QfModule {
    override val id = "privileged"
    override val label = "Privileged dumpsys/processes/logs"

    override fun collect(sink: ArtifactSink): ModuleOutput {
        val shell = QfShell(context)
        if (!shell.available) {
            return ModuleOutput(
                ModuleStatus.PARTIAL,
                emptyList(),
                "android.permission.DUMP is not granted; run the one-time ADB setup"
            )
        }
        val artifacts = ArrayList<String>()
        val errors = ArrayList<String>()
        val commandLog = StringBuilder("command,exit,bytes\n")
        val dumpsys = StringBuilder()
        for (tokens in QfCommands.table) {
            val output = shell.run(tokens)
            val command = tokens.joinToString(" ")
            commandLog.append(command).append(',')
                .append(output.exitCode).append(',')
                .append(output.text.toByteArray().size).append('\n')
            val target = when {
                command.endsWith("getprop") -> "getprop.txt"
                command.endsWith("ps -A") -> "processes.txt"
                command.endsWith("service list") -> "services.txt"
                command.contains("logcat") -> "logs/logcat.txt"
                command.contains("ss ") -> "sockets.txt"
                command.contains("netstat ") -> "sockets_netstat.txt"
                command.startsWith("/system/bin/dumpsys ") -> {
                    val topic = tokens.last()
                    dumpsys.append("\n===== $topic =====\n").append(output.text)
                    "dumpsys_$topic.txt"
                }
                else -> null
            }
            if (target != null) {
                artifacts.add(sink.text(target, output.text))
            }
            if (output.exitCode != 0 || output.error != null || output.truncated) {
                errors.add("$command: ${output.error ?: "exit ${output.exitCode}"}")
            }
        }
        artifacts.add(sink.text("dumpsys.txt", dumpsys.toString()))
        artifacts.add(sink.text("command.log", commandLog.toString()))
        return ModuleOutput(
            if (errors.isEmpty()) ModuleStatus.COMPLETED else ModuleStatus.PARTIAL,
            artifacts,
            errors.joinToString("; ").ifBlank { null }
        )
    }
}

private fun Cursor.getStringOrNull(index: Int): String? =
    if (isNull(index)) null else getString(index)

private fun sha256(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
