package com.ecrew.toolkit.intercept

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.os.IBinder
import com.ecrew.toolkit.audit.AuditShizuku
import com.ecrew.toolkit.audit.ShizukuState
import rikka.shizuku.Shizuku
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

data class ProxyToggleResult(
    val success: Boolean,
    val previous: String?,
    val applied: String?,
    val error: String?
)

/**
 * Option A only: global proxy writes go through a dedicated Shizuku shell user service.
 * The controller never calls Settings.Global and never falls back silently. A failed write
 * leaves the previous value untouched and returns a typed error for the manual guide.
 */
class ShizukuProxyController(context: Context) : AutoCloseable {
    private val appContext = context.applicationContext
    private val lock = Object()
    private var service: IProxyShellService? = null
    private var binding = false
    private val ready = CountDownLatch(1)
    private var bound = false

    private val args = Shizuku.UserServiceArgs(
        ComponentName(appContext.packageName, ProxyUserService::class.java.name)
    )
        .daemon(false)
        .processNameSuffix(PROCESS_SUFFIX)
        .debuggable(false)
        .version(SERVICE_VERSION)

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val proxy = if (binder == null) null else IProxyShellService.Stub.asInterface(binder)
            synchronized(lock) {
                service = proxy
                binding = false
            }
            ready.countDown()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            synchronized(lock) {
                service = null
                binding = false
            }
        }
    }

    val available: Boolean get() = AuditShizuku.state(appContext) == ShizukuState.READY

    fun previous(): String? {
        val proxy = bind() ?: return null
        return try {
            proxy.proxy
        } catch (_: Exception) {
            null
        }
    }

    fun apply(host: String, port: Int): ProxyToggleResult {
        if (!available) {
            return ProxyToggleResult(
                false, null, null,
                "Shizuku is not ready. Use the manual Wi-Fi proxy guide; nothing was changed."
            )
        }
        val proxy = bind() ?: return ProxyToggleResult(
            false, null, null,
            "The Shizuku proxy user service did not bind; nothing was changed."
        )
        val old = try {
            proxy.proxy
        } catch (_: Exception) {
            null
        }
        val code = try {
            proxy.setProxy(host, port)
        } catch (error: Exception) {
            -1
        }
        return if (code == 0) {
            ProxyToggleResult(true, old, "$host:$port", null)
        } else {
            ProxyToggleResult(
                false, old, null,
                "The Shizuku settings write was refused (code $code). Nothing was changed."
            )
        }
    }

    fun restore(previous: String?): ProxyToggleResult {
        val proxy = bind() ?: return ProxyToggleResult(
            false, previous, null, "The Shizuku proxy user service did not bind."
        )
        val code = try {
            proxy.restoreProxy(previous ?: "null")
        } catch (_: Exception) {
            -1
        }
        return if (code == 0) {
            ProxyToggleResult(true, previous, previous, null)
        } else {
            ProxyToggleResult(
                false, previous, null,
                "The global proxy restore failed (code $code). Remove it manually in Settings."
            )
        }
    }

    private fun bind(): IProxyShellService? {
        synchronized(lock) {
            service?.let { return it }
            if (binding) {
                // Wait below for the existing bind.
            } else {
                binding = true
                try {
                    Shizuku.bindUserService(args, connection)
                    bound = true
                } catch (_: Throwable) {
                    binding = false
                    return null
                }
            }
        }
        return try {
            ready.await(10, TimeUnit.SECONDS)
            synchronized(lock) { service }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        }
    }

    override fun close() {
        if (bound) {
            try {
                Shizuku.unbindUserService(args, connection, true)
            } catch (_: Throwable) {
                // The Shizuku binder may already be gone.
            }
        }
        bound = false
        synchronized(lock) {
            service = null
            binding = false
        }
    }

    private companion object {
        const val PROCESS_SUFFIX = "intercept_proxy"
        const val SERVICE_VERSION = 1
    }
}
