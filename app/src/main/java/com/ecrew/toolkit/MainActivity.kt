package com.ecrew.toolkit

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.ecrew.toolkit.ai.AiIntake
import com.ecrew.toolkit.apk.ApkFileIntake
import com.ecrew.toolkit.messaging.MessagingBus
import com.ecrew.toolkit.messaging.MessagingService
import com.ecrew.toolkit.ui.theme.ForensicToolkitTheme
import com.ecrew.toolkit.ui.screens.*
import com.ecrew.toolkit.util.Blocklist
import com.ecrew.toolkit.util.YaraEngine

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Load offline threat intel (bundled blocklist + YARA rules) exactly once.
        Blocklist.init(applicationContext)
        YaraEngine.init(applicationContext)
        // Notification tap for an incoming chat message: ask MainScreen to open Chat.
        if (intent?.getBooleanExtra(MessagingService.EXTRA_OPEN_CHAT, false) == true) {
            MessagingBus.openChatRequested = true
        }
        // "Ask Xairex" handoff from a result screen: open Chat, then the assistant.
        if (intent?.getBooleanExtra(AiIntake.EXTRA_OPEN_XAIREX, false) == true) {
            AiIntake.openRequested = true
        }
        ApkFileIntake.accept(intent)
        setContent {
            ForensicToolkitTheme {
                MainScreen()
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.getBooleanExtra(MessagingService.EXTRA_OPEN_CHAT, false)) {
            MessagingBus.openChatRequested = true
        }
        if (intent.getBooleanExtra(AiIntake.EXTRA_OPEN_XAIREX, false)) {
            AiIntake.openRequested = true
        }
        ApkFileIntake.accept(intent)
    }

    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    override fun onBackPressed() {
        // System back pops the NavHost back stack, which disposes the current
        // destination's composition. If the TerminalView inside its AndroidView still
        // holds focus, ViewGroup.removeAllViewsInLayout() requests focus for the
        // Compose root while the semantics tree is being rebuilt; the accessibility
        // event raised by that focus change walks a detached LayoutNode and crashes
        // with "LayoutNode should be attached to an owner"
        // (AndroidViewHolder.android.kt:340). Clearing the interop focus before the
        // dispose starts keeps the removal event-free.
        currentFocus?.clearFocus()
        super.onBackPressed()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen() {
    val navController = rememberNavController()
    // AndroidComposeView that hosts this composition; used to drop interop focus before
    // a destination change disposes a focused AndroidView (see onBackPressed() for the
    // full failure description).
    val hostView = LocalView.current
    val items = listOf(
        Screen.QRScanner,
        Screen.Terminal,
        Screen.WiFiSuite,
        Screen.Forensics,
        Screen.RemoteSupport,
        Screen.Chat
    )
    // rememberSaveable so the highlight survives the activity recreation the framework
    // performs on configuration changes; otherwise the restored NavHost destination and
    // the bottom bar disagree after a rotation. Hoisted to the screen scope so the
    // chat-notification deep link can select the Chat item programmatically.
    var selectedItem by rememberSaveable { mutableStateOf(0) }
    val backStackEntry by navController.currentBackStackEntryAsState()
    val gamesRouteVisible = backStackEntry?.destination?.route == Screen.Games.route

    LaunchedEffect(MessagingBus.openChatRequested) {
        if (MessagingBus.openChatRequested) {
            hostView.findFocus()?.clearFocus()
            selectedItem = items.indexOf(Screen.Chat)
            navController.navigate(Screen.Chat.route) { launchSingleTop = true }
            MessagingBus.openChatRequested = false
        }
    }

    LaunchedEffect(ApkFileIntake.pendingUri) {
        if (ApkFileIntake.pendingUri != null) {
            hostView.findFocus()?.clearFocus()
            selectedItem = items.indexOf(Screen.Forensics)
            navController.navigate(Screen.Forensics.route) { launchSingleTop = true }
        }
    }

    Scaffold(
        bottomBar = {
            if (!gamesRouteVisible) {
                NavigationBar {
                    items.forEachIndexed { index, screen ->
                        NavigationBarItem(
                            icon = { Icon(screen.icon, contentDescription = screen.title) },
                            selected = selectedItem == index,
                            onClick = {
                                // A focused TerminalView must not be detached: its removal
                                // requests root focus mid-recomposition and the accessibility
                                // walk of the detached semantics tree crashes the app (see
                                // onBackPressed() above).
                                hostView.findFocus()?.clearFocus()
                                selectedItem = index
                                navController.navigate(screen.route)
                            }
                        )
                    }
                }
            }
        }
    ) { innerPadding ->
        NavHost(navController, startDestination = Screen.QRScanner.route, Modifier.padding(innerPadding)) {
            composable(Screen.QRScanner.route) {
                QRScannerScreen(
                    onOpenGames = {
                        hostView.findFocus()?.clearFocus()
                        navController.navigate(Screen.Games.route) { launchSingleTop = true }
                    }
                )
            }
            composable(Screen.Terminal.route) { TerminalScreen() }
            composable(Screen.WiFiSuite.route) { WiFiSuiteScreen() }
            composable(Screen.Forensics.route) { ForensicsScreen() }
            composable(Screen.RemoteSupport.route) { RemoteSupportScreen() }
            composable(Screen.Chat.route) { MessagingScreen() }
            composable(Screen.Games.route) {
                GamesHubScreen(
                    onBack = {
                        hostView.findFocus()?.clearFocus()
                        navController.popBackStack()
                    }
                )
            }
        }
    }
}

