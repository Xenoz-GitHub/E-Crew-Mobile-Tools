package com.ecrew.toolkit.forensics

import android.annotation.SuppressLint
import android.content.ContentValues
import android.content.Context
import android.content.pm.ApplicationInfo
import android.media.MediaScannerConnection
import android.os.Build
import android.os.Environment
import android.provider.CallLog
import android.provider.ContactsContract
import android.provider.MediaStore
import android.provider.Telephony
import androidx.annotation.RequiresApi
import com.ecrew.protocol.Json
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Forensics acquisition helpers (Phase 7), root-free:
 *  - Contacts / SMS / call log read via ContentResolver. The screen requests
 *    READ_CONTACTS / READ_SMS / READ_CALL_LOG at runtime before calling these
 *    (flow-based grant, which lint cannot trace, hence the suppressions).
 *  - Installed-package enumeration (label, version, APK path, size) plus
 *    on-demand SHA-256 hashing of an APK for integrity records.
 *  - Case export: one timestamped folder under Download/E-Crew/cases with a
 *    JSON file per acquired dataset plus a manifest; MediaStore on API 29+,
 *    the legacy public-Downloads path on 26-28 (same split as the audit export).
 */
object ForensicsKit {

    data class ContactRecord(val name: String, val number: String, val type: String)

    data class SmsRecord(
        val address: String,
        val date: Long,
        val direction: String,
        val body: String
    )

    data class CallRecord(
        val number: String,
        val name: String,
        val type: String,
        val date: Long,
        val durationSeconds: Long
    )

    data class AppRecord(
        val label: String,
        val packageName: String,
        val versionName: String,
        val apkPath: String,
        val apkBytes: Long,
        val system: Boolean
    )

    // ------------------------------------------------------------- acquisition

    @SuppressLint("MissingPermission") // granted via the screen's permission flow
    fun readContacts(context: Context, limit: Int = 20_000): List<ContactRecord> {
        val out = ArrayList<ContactRecord>()
        val projection = arrayOf(
            ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
            ContactsContract.CommonDataKinds.Phone.NUMBER,
            ContactsContract.CommonDataKinds.Phone.TYPE
        )
        context.contentResolver.query(
            ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
            projection, null, null,
            ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME + " ASC"
        )?.use { c ->
            val nameIdx = c.getColumnIndexOrThrow(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME)
            val numberIdx = c.getColumnIndexOrThrow(ContactsContract.CommonDataKinds.Phone.NUMBER)
            val typeIdx = c.getColumnIndexOrThrow(ContactsContract.CommonDataKinds.Phone.TYPE)
            while (c.moveToNext() && out.size < limit) {
                out.add(
                    ContactRecord(
                        name = c.getString(nameIdx) ?: "",
                        number = c.getString(numberIdx) ?: "",
                        type = phoneTypeLabel(c.getInt(typeIdx))
                    )
                )
            }
        }
        return out
    }

    @SuppressLint("MissingPermission") // granted via the screen's permission flow
    fun readSms(context: Context, limit: Int = 20_000): List<SmsRecord> {
        val out = ArrayList<SmsRecord>()
        val projection = arrayOf(
            Telephony.Sms.ADDRESS,
            Telephony.Sms.DATE,
            Telephony.Sms.TYPE,
            Telephony.Sms.BODY
        )
        context.contentResolver.query(
            Telephony.Sms.CONTENT_URI,
            projection, null, null,
            Telephony.Sms.DATE + " DESC"
        )?.use { c ->
            val addressIdx = c.getColumnIndexOrThrow(Telephony.Sms.ADDRESS)
            val dateIdx = c.getColumnIndexOrThrow(Telephony.Sms.DATE)
            val typeIdx = c.getColumnIndexOrThrow(Telephony.Sms.TYPE)
            val bodyIdx = c.getColumnIndexOrThrow(Telephony.Sms.BODY)
            while (c.moveToNext() && out.size < limit) {
                out.add(
                    SmsRecord(
                        address = c.getString(addressIdx) ?: "",
                        date = c.getLong(dateIdx),
                        direction = smsDirectionLabel(c.getInt(typeIdx)),
                        body = c.getString(bodyIdx) ?: ""
                    )
                )
            }
        }
        return out
    }

    @SuppressLint("MissingPermission") // granted via the screen's permission flow
    fun readCalls(context: Context, limit: Int = 20_000): List<CallRecord> {
        val out = ArrayList<CallRecord>()
        val projection = arrayOf(
            CallLog.Calls.NUMBER,
            CallLog.Calls.CACHED_NAME,
            CallLog.Calls.TYPE,
            CallLog.Calls.DATE,
            CallLog.Calls.DURATION
        )
        context.contentResolver.query(
            CallLog.Calls.CONTENT_URI,
            projection, null, null,
            CallLog.Calls.DATE + " DESC"
        )?.use { c ->
            val numberIdx = c.getColumnIndexOrThrow(CallLog.Calls.NUMBER)
            val nameIdx = c.getColumnIndexOrThrow(CallLog.Calls.CACHED_NAME)
            val typeIdx = c.getColumnIndexOrThrow(CallLog.Calls.TYPE)
            val dateIdx = c.getColumnIndexOrThrow(CallLog.Calls.DATE)
            val durationIdx = c.getColumnIndexOrThrow(CallLog.Calls.DURATION)
            while (c.moveToNext() && out.size < limit) {
                out.add(
                    CallRecord(
                        number = c.getString(numberIdx) ?: "",
                        name = c.getString(nameIdx) ?: "",
                        type = callTypeLabel(c.getInt(typeIdx)),
                        date = c.getLong(dateIdx),
                        durationSeconds = c.getLong(durationIdx)
                    )
                )
            }
        }
        return out
    }

    @Suppress("DEPRECATION") // getPackageInfo(String, int) covers all supported API levels
    fun readInstalledApps(context: Context): List<AppRecord> {
        val pm = context.packageManager
        return pm.getInstalledApplications(0)
            .map { ai ->
                val apk = File(ai.sourceDir)
                AppRecord(
                    label = runCatching { ai.loadLabel(pm).toString() }.getOrDefault(ai.packageName),
                    packageName = ai.packageName,
                    versionName = runCatching {
                        pm.getPackageInfo(ai.packageName, 0).versionName ?: ""
                    }.getOrDefault(""),
                    apkPath = ai.sourceDir ?: "",
                    apkBytes = if (apk.exists()) apk.length() else 0L,
                    system = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                )
            }
            .sortedBy { it.label.lowercase(Locale.US) }
    }

    fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(16 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                digest.update(buf, 0, n)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    // ------------------------------------------------------------ case export

    /** Writes every non-empty dataset plus a manifest into one case folder. */
    fun exportCase(
        context: Context,
        contacts: List<ContactRecord>,
        sms: List<SmsRecord>,
        calls: List<CallRecord>,
        apps: List<AppRecord>
    ): Result<String> {
        if (contacts.isEmpty() && sms.isEmpty() && calls.isEmpty() && apps.isEmpty()) {
            return Result.failure(IllegalStateException("nothing acquired yet"))
        }
        val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val folder = "ecrew-case_$stamp"
        val files = linkedMapOf<String, String>()
        if (contacts.isNotEmpty()) {
            files["contacts.json"] = Json.encode(
                contacts.map { mapOf("name" to it.name, "number" to it.number, "type" to it.type) }
            )
        }
        if (sms.isNotEmpty()) {
            files["sms.json"] = Json.encode(
                sms.map {
                    mapOf(
                        "address" to it.address,
                        "date" to it.date,
                        "direction" to it.direction,
                        "body" to it.body
                    )
                }
            )
        }
        if (calls.isNotEmpty()) {
            files["calls.json"] = Json.encode(
                calls.map {
                    mapOf(
                        "number" to it.number,
                        "name" to it.name,
                        "type" to it.type,
                        "date" to it.date,
                        "durationSeconds" to it.durationSeconds
                    )
                }
            )
        }
        if (apps.isNotEmpty()) {
            files["apps.json"] = Json.encode(
                apps.map {
                    mapOf(
                        "label" to it.label,
                        "package" to it.packageName,
                        "version" to it.versionName,
                        "apkPath" to it.apkPath,
                        "apkBytes" to it.apkBytes,
                        "system" to it.system
                    )
                }
            )
        }
        files["manifest.json"] = Json.encode(
            linkedMapOf<String, Any?>(
                "type" to "ecrew-case",
                "generatedAt" to System.currentTimeMillis(),
                "device" to "${Build.MANUFACTURER} ${Build.MODEL}",
                "androidRelease" to Build.VERSION.RELEASE,
                "androidSdk" to Build.VERSION.SDK_INT,
                "counts" to linkedMapOf<String, Any?>(
                    "contacts" to contacts.size,
                    "sms" to sms.size,
                    "calls" to calls.size,
                    "apps" to apps.size
                )
            )
        )
        return if (Build.VERSION.SDK_INT >= 29) {
            exportViaMediaStore(context, folder, files)
        } else {
            exportLegacy(context, folder, files)
        }
    }

    @RequiresApi(Build.VERSION_CODES.Q) // caller (exportCase) dispatches on the API level
    private fun exportViaMediaStore(
        context: Context,
        folder: String,
        files: Map<String, String>
    ): Result<String> {
        val resolver = context.contentResolver
        return try {
            for ((name, content) in files) {
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.MIME_TYPE, "application/json")
                    put(MediaStore.Downloads.RELATIVE_PATH, "Download/E-Crew/cases/$folder")
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }
                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?: return Result.failure(IllegalStateException("MediaStore refused $name"))
                resolver.openOutputStream(uri)?.use { out ->
                    out.write(content.toByteArray(Charsets.UTF_8))
                } ?: return Result.failure(IllegalStateException("cannot open $name"))
                values.clear()
                values.put(MediaStore.Downloads.IS_PENDING, 0)
                resolver.update(uri, values, null, null)
            }
            Result.success("Download/E-Crew/cases/$folder")
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    @Suppress("DEPRECATION") // legacy public-Downloads path is only used on API 26-28
    private fun exportLegacy(
        context: Context,
        folder: String,
        files: Map<String, String>
    ): Result<String> {
        return try {
            val downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val dir = File(downloads, "E-Crew/cases/$folder")
            if (!dir.exists() && !dir.mkdirs()) {
                return Result.failure(IllegalStateException("cannot create ${dir.absolutePath}"))
            }
            for ((name, content) in files) {
                val file = File(dir, name)
                file.writeText(content, Charsets.UTF_8)
                MediaScannerConnection.scanFile(context, arrayOf(file.absolutePath), null, null)
            }
            Result.success(dir.absolutePath)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // ---------------------------------------------------------------- labels

    private fun phoneTypeLabel(type: Int): String = when (type) {
        ContactsContract.CommonDataKinds.Phone.TYPE_HOME -> "home"
        ContactsContract.CommonDataKinds.Phone.TYPE_MOBILE -> "mobile"
        ContactsContract.CommonDataKinds.Phone.TYPE_WORK -> "work"
        ContactsContract.CommonDataKinds.Phone.TYPE_FAX_WORK -> "fax_work"
        ContactsContract.CommonDataKinds.Phone.TYPE_FAX_HOME -> "fax_home"
        ContactsContract.CommonDataKinds.Phone.TYPE_PAGER -> "pager"
        ContactsContract.CommonDataKinds.Phone.TYPE_OTHER -> "other"
        else -> "type_$type"
    }

    private fun smsDirectionLabel(type: Int): String = when (type) {
        Telephony.Sms.MESSAGE_TYPE_INBOX -> "inbox"
        Telephony.Sms.MESSAGE_TYPE_SENT -> "sent"
        Telephony.Sms.MESSAGE_TYPE_DRAFT -> "draft"
        Telephony.Sms.MESSAGE_TYPE_OUTBOX -> "outbox"
        Telephony.Sms.MESSAGE_TYPE_FAILED -> "failed"
        Telephony.Sms.MESSAGE_TYPE_QUEUED -> "queued"
        else -> "type_$type"
    }

    private fun callTypeLabel(type: Int): String = when (type) {
        CallLog.Calls.INCOMING_TYPE -> "incoming"
        CallLog.Calls.OUTGOING_TYPE -> "outgoing"
        CallLog.Calls.MISSED_TYPE -> "missed"
        CallLog.Calls.VOICEMAIL_TYPE -> "voicemail"
        CallLog.Calls.REJECTED_TYPE -> "rejected"
        CallLog.Calls.BLOCKED_TYPE -> "blocked"
        else -> "type_$type"
    }
}
