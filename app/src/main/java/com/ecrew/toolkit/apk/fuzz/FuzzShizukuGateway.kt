package com.ecrew.toolkit.apk.fuzz

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.os.IBinder
import com.ecrew.toolkit.audit.AuditShizuku
import com.ecrew.toolkit.audit.ShizukuState
import rikka.shizuku.Shizuku
import java.io.ByteArrayOutputStream
import java.io.Closeable

data class CrashCapture(
    val stdout: String,
    val error: String?,
    val exitCode: Int,
    val degraded: Boolean
)

/**
 * Binds the fuzz-specific Shizuku user service lazily. The service exposes only three fixed
 * crash-capture modes; no caller-provided command text reaches the served process. Binding is
 * attempted only when fuzzing starts, never at app launch.
 */
class FuzzShizukuGateway(context: Context) : Closeable {
    private val appContext = context.applicationContext
    private val lock = Object()
    private var service: IFuzzShellService? = null
    private var binding = false

    private val args = Shizuku.UserServiceArgs(
        ComponentName(appContext.packageName, FuzzUserService::class.java.name)
    )
        .daemon(false)
        .processNameSuffix(PROCESS_SUFFIX)
        .debuggable(false)
        .version(SERVICE_VERSION)

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            synchronized(lock) {
                service = binder?.let { IFuzzShellService.Stub.asInterface(it) }
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

    val ready: Boolean get() = AuditShizuku.state(appContext) == ShizukuState.READY

    fun capture(mode: Int): CrashCapture {
        if (!ready) {
            return CrashCapture("", "Shizuku is not ready; crash capture is degraded", -1, true)
        }
        val bound = serviceOrNull()
            ?: return CrashCapture("", "the fuzz Shizuku service is unavailable", -1, true)
        val total = try {
            bound.capture(mode)
        } catch (error: Exception) {
            synchronized(lock) { service = null }
            return CrashCapture("", "crash capture call failed: ${error.javaClass.simpleName}", -1, true)
        }
        val errorText = try {
            bound.stderr()
        } catch (_: Exception) {
            ""
        }
        if (total < 0) {
            return CrashCapture("", errorText.ifBlank { "crash capture rejected" }, total, true)
        }
        val out = ByteArrayOutputStream(total)
        var offset = 0
        while (offset < total) {
            val chunk = try {
                bound.read(offset, minOf(CHUNK_BYTES, total - offset))
            } catch (error: Exception) {
                synchronized(lock) { service = null }
                return CrashCapture("", "crash capture read failed", -1, true)
            }
            if (chunk.isEmpty()) {
                return CrashCapture("", "crash capture ended early", -1, true)
            }
            out.write(chunk)
            offset += chunk.size
        }
        val exit = try {
            bound.exitCode()
        } catch (_: Exception) {
            -1
        }
        return CrashCapture(out.toByteArray().toString(Charsets.UTF_8), null, exit, false)
    }

    override fun close() {
        try {
            Shizuku.unbindUserService(args, connection, true)
        } catch (_: Throwable) {
            // The Shizuku binder may already be gone.
        }
        synchronized(lock) {
            service = null
        }
    }

    private fun serviceOrNull(): IFuzzShellService? {
        synchronized(lock) {
            service?.let { return it }
            if (!binding) {
                binding = true
                try {
                    Shizuku.bindUserService(args, connection)
                } catch (error: Throwable) {
                    binding = false
                    return null
                }
            }
            val deadline = System.currentTimeMillis() + BIND_TIMEOUT_MS
            while (service == null && binding) {
                val remaining = deadline - System.currentTimeMillis()
                if (remaining <= 0) break
                try {
                    lock.wait(remaining)
                } catch (error: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                }
            }
            return service
        }
    }

    private companion object {
        const val PROCESS_SUFFIX = ":fuzz"
        const val SERVICE_VERSION = 1
        const val CHUNK_BYTES = 64 * 1024
        const val BIND_TIMEOUT_MS = 10_000L
    }
}
