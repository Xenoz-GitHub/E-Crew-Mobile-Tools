package com.ecrew.toolkit.ui.screens

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.ui.graphics.vector.ImageVector

sealed class Screen(val route: String, val title: String, val icon: ImageVector) {
    object QRScanner : Screen("qr_scanner", "QR Scanner", Icons.Default.QrCodeScanner)
    object Terminal : Screen("terminal", "Terminal", Icons.Default.Terminal)
    object WiFiSuite : Screen("wifi_suite", "Wi-Fi Suite", Icons.Default.Wifi)
    object Forensics : Screen("forensics", "Forensics", Icons.Default.Search)
    object RemoteSupport : Screen("remote_support", "Remote", Icons.Default.SupportAgent)
    object Chat : Screen("chat", "Chat", Icons.Default.Chat)

    /** Not a bottom-nav item: opened from the QR scanner's Games Hub entry. */
    object Games : Screen("games", "Games Hub", Icons.Default.Star)
}

