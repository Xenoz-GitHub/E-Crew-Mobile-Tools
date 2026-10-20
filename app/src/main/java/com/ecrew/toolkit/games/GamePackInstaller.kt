package com.ecrew.toolkit.games

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.widget.Toast
import androidx.annotation.WorkerThread

/**
 * Installs an APK from the app's assets into Android's package manager and launches it.
 *
 * Android does not permit a normal sideloaded app to install another APK silently. The
 * session commit intentionally triggers the system installer confirmation prompt.
 */
object GamePackInstaller {
    internal const val ACTION_INSTALL_STATUS = "com.ecrew.toolkit.games.action.PACK_INSTALL_STATUS"
    internal const val EXTRA_PACKAGE = "com.ecrew.toolkit.games.extra.PACKAGE"
    internal const val EXTRA_ACTIVITY = "com.ecrew.toolkit.games.extra.ACTIVITY"
    internal const val EXTRA_TITLE = "com.ecrew.toolkit.games.extra.TITLE"

    private const val COPY_BUFFER = 1024 * 1024

    fun isInstalled(context: Context, pack: GamePack): Boolean =
        try {
            context.packageManager.getPackageInfo(pack.packageName, 0)
            true
        } catch (_: Exception) {
            false
        }

    fun isBundled(context: Context, pack: GamePack): Boolean =
        try {
            context.assets.list("")?.contains(pack.assetName) == true
        } catch (_: Exception) {
            false
        }

    fun canInstall(context: Context): Boolean =
        context.packageManager.canRequestPackageInstalls()

    fun supportsNativeAbi(pack: GamePack): Boolean =
        Build.SUPPORTED_ABIS.any { deviceAbi ->
            pack.nativeAbis.any { packAbi -> packAbi.equals(deviceAbi, ignoreCase = true) }
        }

    fun openInstallPermissionSettings(context: Context) {
        val packageUri = Uri.parse("package:${context.packageName}")
        val direct = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, packageUri)
        direct.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (runCatching { context.startActivity(direct) }.isSuccess) return

        val fallback = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, packageUri)
        fallback.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (runCatching { context.startActivity(fallback) }.isFailure) {
            Toast.makeText(
                context,
                "Open Settings and allow installs for E-Crew Toolkit.",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    fun launch(context: Context, pack: GamePack): Boolean {
        val launch = context.packageManager.getLaunchIntentForPackage(pack.packageName)
            ?: Intent().setClassName(pack.packageName, pack.launchActivity)
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED)
        return try {
            context.startActivity(launch)
            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Streams the pack APK from the app's assets into a PackageInstaller session and
     * commits it. The system installer UI is opened by [GamePackInstallReceiver].
     */
    @WorkerThread
    fun installBundled(context: Context, pack: GamePack) {
        context.assets.open(pack.assetName).use { input ->
            installStream(context, pack, input)
        }
    }

    /**
     * Streams a user-selected pack APK into a PackageInstaller session and commits it.
     * The caller owns [source] and closes it after this method returns.
     */
    @WorkerThread
    fun installStream(context: Context, pack: GamePack, source: java.io.InputStream) {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(
            PackageInstaller.SessionParams.MODE_FULL_INSTALL
        ).apply {
            setAppPackageName(pack.packageName)
            setInstallLocation(PackageInfo.INSTALL_LOCATION_AUTO)
        }

        val sessionId = installer.createSession(params)
        var session: PackageInstaller.Session? = null
        try {
            session = installer.openSession(sessionId)
            session.openWrite("base.apk", 0, -1).use { output ->
                source.copyTo(output, COPY_BUFFER)
                session.fsync(output)
            }

            val callback = Intent(context, GamePackInstallReceiver::class.java).apply {
                action = ACTION_INSTALL_STATUS
                putExtra(EXTRA_PACKAGE, pack.packageName)
                putExtra(EXTRA_ACTIVITY, pack.launchActivity)
                putExtra(EXTRA_TITLE, pack.title)
            }
            val flags = PendingIntentFlags.forInstaller()
            val pending = android.app.PendingIntent.getBroadcast(
                context,
                sessionId,
                callback,
                flags
            )
            session.commit(pending.intentSender)
        } catch (error: Throwable) {
            runCatching { session?.abandon() }
            throw error
        } finally {
            runCatching { session?.close() }
        }
    }

    private object PendingIntentFlags {
        fun forInstaller(): Int {
            val update = android.app.PendingIntent.FLAG_UPDATE_CURRENT
            // The installer fills status extras into this broadcast. Android 12+ requires
            // mutable PendingIntents for that; older releases ignore the extra flag.
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                update or android.app.PendingIntent.FLAG_MUTABLE
            } else {
                update
            }
        }
    }
}
