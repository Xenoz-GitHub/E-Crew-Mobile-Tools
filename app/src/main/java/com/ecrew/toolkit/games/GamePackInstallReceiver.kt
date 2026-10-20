package com.ecrew.toolkit.games

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.widget.Toast

/**
 * Receives the PackageInstaller result for a Games Hub pack. On success it opens the
 * installed game immediately; otherwise it reports the failure without crashing the Hub.
 */
class GamePackInstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != GamePackInstaller.ACTION_INSTALL_STATUS) return

        when (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> openConfirmation(context, intent)
            PackageInstaller.STATUS_SUCCESS -> openInstalledGame(context, intent)
            else -> showFailure(context, intent)
        }
    }

    private fun openConfirmation(context: Context, intent: Intent) {
        @Suppress("DEPRECATION")
        val confirmation = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
        if (confirmation == null) {
            Toast.makeText(context, "Installer prompt was unavailable.", Toast.LENGTH_LONG).show()
            return
        }
        confirmation.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (runCatching { context.startActivity(confirmation) }.isFailure) {
            Toast.makeText(
                context,
                "Open Games Hub and tap Install again to finish.",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun openInstalledGame(context: Context, intent: Intent) {
        val title = intent.getStringExtra(GamePackInstaller.EXTRA_TITLE) ?: "Game pack"
        val packageName = intent.getStringExtra(GamePackInstaller.EXTRA_PACKAGE)
        val activity = intent.getStringExtra(GamePackInstaller.EXTRA_ACTIVITY)
        Toast.makeText(context, "$title installed.", Toast.LENGTH_SHORT).show()
        if (packageName == null) return

        val launch = context.packageManager.getLaunchIntentForPackage(packageName)
            ?: activity?.let { Intent().setClassName(packageName, it) }
            ?: return
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED)
        if (runCatching { context.startActivity(launch) }.isFailure) {
            Toast.makeText(
                context,
                "Installed. Tap $title in Games Hub to play.",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun showFailure(context: Context, intent: Intent) {
        val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
        val reason = if (message.isNullOrBlank()) "Install cancelled." else "Install failed: $message"
        Toast.makeText(context, reason, Toast.LENGTH_LONG).show()
    }
}
