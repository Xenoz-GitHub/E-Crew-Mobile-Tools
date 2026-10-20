package com.ecrew.toolkit.audit

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.IBinder
import rikka.shizuku.Shizuku
import java.io.ByteArrayOutputStream

/**
 * Shizuku tier support (design note section 9c).
 *
 * E-Crew never installs, downloads or starts Shizuku, and it requests the Shizuku permission
 * only after the operator taps "Request access" in the Audit tab. All privileged reads go
 * through [ShizukuShell], which binds the official Shizuku user service and executes only the
 * frozen [AuditCommands.shizukuTable].
 */

/** The Shizuku state as the audit sees it. */
enum class ShizukuState {
    NOT_INSTALLED,
    NOT_RUNNING,
    PERMISSION_REQUIRED,
    READY
}

/** Thin, defensive wrapper around the Shizuku API; every call can outlive the service. */
object AuditShizuku {

    /** The stable Shizuku manager package; other builds use a different id. */
    const val MANAGER_PACKAGE = "moe.shizuku.privileged.api"

    /** Request code for the permission dialog; the result arrives via the listener. */
    const val REQUEST_CODE = 0x5348

    fun state(context: Context): ShizukuState {
        val running = try {
            Shizuku.pingBinder()
        } catch (e: Throwable) {
            false
        }
        if (!running) {
            return if (isInstalled(context)) ShizukuState.NOT_RUNNING else ShizukuState.NOT_INSTALLED
        }
        val granted = try {
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        } catch (e: Throwable) {
            false
        }
        return if (granted) ShizukuState.READY else ShizukuState.PERMISSION_REQUIRED
    }

    fun isInstalled(context: Context): Boolean = try {
        context.packageManager.getPackageInfo(MANAGER_PACKAGE, 0)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    /** Shows the Shizuku permission dialog. Called only from the user's tap. */
    fun requestPermission(): Boolean = try {
        Shizuku.requestPermission(REQUEST_CODE)
        true
    } catch (e: Throwable) {
        false
    }

    fun addPermissionResultListener(
        onResult: (Boolean) -> Unit
    ): Shizuku.OnRequestPermissionResultListener? = try {
        val listener = Shizuku.OnRequestPermissionResultListener { requestCode, grantResult ->
            if (requestCode == REQUEST_CODE) {
                onResult(grantResult == PackageManager.PERMISSION_GRANTED)
            }
        }
        Shizuku.addRequestPermissionResultListener(listener)
        listener
    } catch (e: Throwable) {
        null
    }

    fun removePermissionResultListener(
        listener: Shizuku.OnRequestPermissionResultListener?
    ): Boolean {
        if (listener == null) return false
        return try {
            Shizuku.removeRequestPermissionResultListener(listener)
        } catch (e: Throwable) {
            false
        }
    }
}

/**
 * [AuditShell] backed by a Shizuku user service.
 *
 * The service is bound lazily on the first command and is non-daemon, so it dies with the app
 * process. [exec] is called from the scan's background thread; [bindUserService] delivers the
 * connection on the app's main thread, therefore [exec] must never run on the main thread.
 * Output is pulled in [CHUNK_BYTES] chunks; transport failures are never cached, while real
 * command results are cached for the duration of the scan (several checks share a dump).
 */
class ShizukuShell(context: Context) : AuditShell {

    override val source: ShellTier = ShellTier.SHIZUKU

    private val appContext = context.applicationContext
    private val lock = Object()
    private val cacheLock = Object()
    private val cache = HashMap<String, ShellResult>()
    private var service: IAuditShellService? = null
    private var binding = false

    private val args = Shizuku.UserServiceArgs(
        ComponentName(appContext.packageName, AuditUserService::class.java.name)
    )
        .daemon(false)
        .processNameSuffix(PROCESS_SUFFIX)
        .debuggable(false)
        .version(SERVICE_VERSION)

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            synchronized(lock) {
                service = binder?.let { IAuditShellService.Stub.asInterface(it) }
                binding = false
                lock.notifyAll()
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            synchronized(lock) {
                service = null
            }
        }
    }

    override fun exec(command: List<String>): ShellResult {
        require(AuditCommands.isShizukuAllowed(command)) {
            "command not in the read-only Shizuku table: ${AuditCommands.canonical(command)}"
        }
        val key = AuditCommands.canonical(command)
        synchronized(cacheLock) {
            cache[key]?.let { return it }
        }
        val result = run(command)
        if (result.exitCode >= 0) {
            synchronized(cacheLock) { cache[key] = result }
        }
        return result
    }

    private fun run(command: List<String>): ShellResult {
        val canonical = AuditCommands.canonical(command)
        val bound = serviceOrNull() ?: return ShellResult(
            command, -1, "", "the Shizuku user service is not available; start Shizuku and grant E-Crew access"
        )
        val total = try {
            bound.execute(canonical)
        } catch (e: Exception) {
            synchronized(lock) { service = null }
            return ShellResult(
                command, -1, "",
                "Shizuku call failed: ${e.javaClass.simpleName}: ${e.message ?: "no message"}"
            )
        }
        val errorText = try {
            bound.stderr()
        } catch (e: Exception) {
            ""
        }
        if (total < 0) {
            return ShellResult(
                command, total, "",
                errorText.ifBlank { "the Shizuku user service rejected the command" }
            )
        }
        val out = ByteArrayOutputStream(total)
        var offset = 0
        while (offset < total) {
            val length = minOf(CHUNK_BYTES, total - offset)
            val chunk = try {
                bound.read(offset, length)
            } catch (e: Exception) {
                synchronized(lock) { service = null }
                return ShellResult(
                    command, -1, "",
                    "Shizuku read failed: ${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                )
            }
            if (chunk.isEmpty()) {
                return ShellResult(
                    command, -1, "",
                    "the Shizuku user service ended the output early ($offset of $total bytes)"
                )
            }
            out.write(chunk)
            offset += chunk.size
        }
        val exit = try {
            bound.exitCode()
        } catch (e: Exception) {
            -1
        }
        return ShellResult(command, exit, out.toByteArray().toString(Charsets.UTF_8), errorText)
    }

    /**
     * Binds the user service once and waits for the connection. The caller is a background
     * thread; the connection callback arrives on the app's main thread. On timeout the next
     * attempt binds again rather than caching a dead service.
     */
    private fun serviceOrNull(): IAuditShellService? {
        synchronized(lock) {
            service?.let { return it }
            if (!binding) {
                binding = true
                try {
                    Shizuku.bindUserService(args, connection)
                } catch (e: Throwable) {
                    binding = false
                    return null
                }
            }
            val deadline = System.currentTimeMillis() + BIND_TIMEOUT_MS
            while (service == null) {
                val remaining = deadline - System.currentTimeMillis()
                if (remaining <= 0) {
                    binding = false
                    return null
                }
                try {
                    lock.wait(remaining)
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    binding = false
                    return null
                }
            }
            return service
        }
    }

    private companion object {
        const val SERVICE_VERSION = 1
        const val PROCESS_SUFFIX = "audit"
        const val BIND_TIMEOUT_MS = 10_000L
        const val CHUNK_BYTES = 256 * 1024
    }
}
