package com.ecrew.toolkit.ui.screens

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import com.ecrew.toolkit.terminal.BootstrapManager
import com.ecrew.toolkit.terminal.SessionClient
import com.ecrew.toolkit.terminal.ViewClient
import com.termux.terminal.TerminalSession
import com.termux.view.TerminalView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/**
 * Real embedded terminal: Termux terminal-view + terminal-emulator (bundled
 * libtermux.so provides the forkpty PTY) driving either the extracted Termux
 * bootstrap bash or the system mksh. No simulation - it is a live shell.
 */
@Composable
fun TerminalScreen() {
    val context = LocalContext.current
    // Host composition view; see the Restart button below for why interop focus is
    // cleared before the session swap.
    val hostView = LocalView.current
    var status by remember {
        mutableStateOf("Extracting Termux bootstrap (first launch, ~30 MB)…")
    }
    var ready by remember { mutableStateOf(false) }
    var sessionVersion by remember { mutableIntStateOf(0) }
    var info by remember { mutableStateOf("starting shell…") }
    var helpOpen by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            val r = BootstrapManager.ensureBootstrapped(context)
            val s2 = if (r.ok) BootstrapManager.runSecondStage(context) else ""
            status = if (r.ok) "${r.message} | $s2"
            else "no rootfs: ${r.message} (system shell fallback)"
            ready = true
        }
    }

    Column(Modifier.fillMaxSize()) {
        if (!ready) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(14.dp))
                    Text(status, fontSize = 11.sp, color = MonoGray)
                }
            }
        } else {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    info,
                    fontSize = 10.sp,
                    color = MonoGray,
                    maxLines = 2,
                    modifier = Modifier.weight(1f)
                )
                OutlinedButton(onClick = { helpOpen = true }) { Text("?", fontSize = 11.sp) }
                Spacer(Modifier.width(6.dp))
                OutlinedButton(onClick = {
                    // The version bump disposes the old AndroidView holder; a focused
                    // TerminalView removed during recomposition raises a root focus event
                    // that crashes the accessibility walk (see MainActivity).
                    hostView.findFocus()?.clearFocus()
                    sessionVersion++
                }) { Text("Restart", fontSize = 11.sp) }
            }

            // The session object is owned per version and captured by value everywhere
            // below; the PTY subprocess itself is started by attachSession() inside the
            // AndroidView factory. SessionHolder-style indirection is intentionally
            // avoided: a dispose must never be able to pick up a newer session whose
            // subprocess has not started yet.
            val sessionClient = remember(sessionVersion) { SessionClient(context) }
            val session = remember(sessionVersion) {
                val shell = BootstrapManager.shellPath(context)
                TerminalSession(
                    shell,
                    BootstrapManager.homeDir(context).absolutePath,
                    arrayOf(shell),
                    BootstrapManager.sessionEnv(context),
                    null,
                    sessionClient
                )
            }

            key(session) {
                Box(Modifier.weight(1f)) {
                    AndroidView(
                        factory = { ctx ->
                            val tv = TerminalView(ctx, null)
                            sessionClient.view = tv
                            tv.setTerminalViewClient(ViewClient(ctx, tv))
                            // terminal-view 0.118.2 never calls setFocusable(); without this
                            // its internal requestFocus() (tap handler) silently fails and
                            // neither hardware keys nor IME input can reach the terminal.
                            tv.isFocusable = true
                            tv.isFocusableInTouchMode = true
                            // Renderer is only created by setTextSize() - required
                            // before attachSession(), otherwise updateSize() NPEs.
                            tv.setTextSize(
                                (14 * ctx.resources.displayMetrics.density *
                                    ctx.resources.configuration.fontScale).toInt()
                            )
                            tv.attachSession(session)
                            tv
                        },
                        update = {
                            it.updateSize()
                            it.requestFocus()
                        }
                    )
                }
            }

            // terminal-emulator 0.118.2 finishIfRunning() = kill(mShellPid, SIGKILL)
            // with isRunning() == (mShellPid != -1), so a session that was created but
            // whose subprocess did not start yet has mShellPid == 0 and kill(0, ...)
            // would signal this app's own process group (instant silent death). Only
            // signal a pid that is definitely a live shell.
            DisposableEffect(session) {
                onDispose {
                    if (session.pid > 0) session.finishIfRunning()
                }
            }

            LaunchedEffect(session) {
                info = withContext(Dispatchers.IO) {
                    // attachSession() runs on the UI thread after this screen's first
                    // composition; poll briefly so the header reports the real shell pid
                    // instead of the pre-start value (0).
                    var pid = session.pid
                    var waited = 0
                    while (pid <= 0 && waited < 2000) {
                        delay(50)
                        waited += 50
                        pid = session.pid
                    }
                    "shell=${BootstrapManager.shellPath(context)} pid=$pid " +
                        "rootfs=${BootstrapManager.isBootstrapped(context)}"
                }
            }

            ExtraKeysRow { session }
        }
    }

    if (helpOpen) TerminalHelpDialog(onDismiss = { helpOpen = false })
}

    /**
     * Forensic-friendly extra keys: sticky CTRL/ALT toggles, ESC/TAB/ENTER,
     * arrow keys and commonly needed shell punctuation.
     */
    @Composable
    private fun ExtraKeysRow(sessionProvider: () -> TerminalSession?) {
        var ctrl by remember { mutableStateOf(false) }
        var alt by remember { mutableStateOf(false) }
        val rowScroll = rememberScrollState()

        fun send(bytes: ByteArray) {
            sessionProvider()?.write(bytes, 0, bytes.size)
        }

        fun sendChar(c: Char) {
            val s = sessionProvider() ?: return
            if (ctrl) {
                val code = c.uppercaseChar().code
                if (code in 64..95) {
                    val b = byteArrayOf((code - 64).toByte())
                    s.write(b, 0, b.size)
                } else send(c.toString().toByteArray())
            } else {
                if (alt) send(byteArrayOf(0x1B))
                send(c.toString().toByteArray())
            }
            ctrl = false
            alt = false
        }

        Row(
            Modifier
                .fillMaxWidth()
                .horizontalScroll(rowScroll)
                .padding(horizontal = 4.dp, vertical = 2.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            KeyBtn("ESC") { send(byteArrayOf(0x1B)) }
            KeyBtn("TAB") { send(byteArrayOf(0x09)) }
            KeyBtn("ENTER") { send(byteArrayOf(0x0D)) }
            KeyBtn("CTRL", ctrl) { ctrl = !ctrl; alt = false }
            KeyBtn("ALT", alt) { alt = !alt; ctrl = false }
            KeyBtn("↑") { send("\u001B[A".toByteArray()) }
            KeyBtn("↓") { send("\u001B[B".toByteArray()) }
            KeyBtn("←") { send("\u001B[D".toByteArray()) }
            KeyBtn("→") { send("\u001B[C".toByteArray()) }
            KeyBtn("/") { sendChar('/') }
            KeyBtn("-") { sendChar('-') }
            KeyBtn("|") { sendChar('|') }
            KeyBtn("~") { sendChar('~') }
            KeyBtn("c") { sendChar('c') }
            KeyBtn("d") { sendChar('d') }
            KeyBtn("l") { sendChar('l') }
            KeyBtn("q") { sendChar('q') }
        }
    }

    @Composable
    private fun KeyBtn(label: String, active: Boolean = false, onClick: () -> Unit) {
        val bg = if (active) Color(0xFF00695C) else Color(0xFF1C252C)
        Button(
            onClick = onClick,
            colors = ButtonDefaults.buttonColors(containerColor = bg),
            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
            modifier = Modifier.defaultMinSize(minHeight = 34.dp)
        ) {
            Text(label, fontSize = 12.sp, color = Color(0xFFCFD8DC))
        }
    }

    /**
     * In-app cheat sheet for the embedded shell: how input reaches the terminal,
     * what the sandbox allows and the commands that are available without root.
     */
    @Composable
    private fun TerminalHelpDialog(onDismiss: () -> Unit) {
        AlertDialog(
            onDismissRequest = onDismiss,
            confirmButton = {
                TextButton(onClick = onDismiss) { Text("Close", fontSize = 12.sp) }
            },
            title = { Text("Terminal help", fontSize = 15.sp) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    Text(
                        "Tap the screen once to focus the shell, then type with the keyboard. " +
                            "TAB completes paths, Up/Down recall history. CTRL is sticky: " +
                            "tap CTRL then c for Ctrl+C. The extra keys row sends ESC, ENTER " +
                            "and common symbols.",
                        fontSize = 12.sp
                    )
                    Spacer(Modifier.height(10.dp))
                    Text(
                        "This shell runs as the app user (not root), so dumpsys, pm and " +
                            "settings do not work here. The dedicated toolkit screens cover " +
                            "those jobs.",
                        fontSize = 12.sp
                    )
                    Spacer(Modifier.height(12.dp))
                    HelpBlock(
                        "Files",
                        "pwd", "ls -la", "cd /sdcard/Download", "cat file", "head -20 file"
                    )
                    HelpBlock(
                        "Device info",
                        "id", "ps -A", "getprop ro.product.model", "df -h", "uptime"
                    )
                    HelpBlock(
                        "Search and filter",
                        "ls -l | grep Download", "grep word file", "find /sdcard -name \"*.jpg\""
                    )
                    HelpBlock(
                        "Hashing",
                        "md5sum file", "sha1sum file", "sha256sum file"
                    )
                    HelpBlock(
                        "Network",
                        "ping 8.8.8.8", "ip addr", "netstat"
                    )
                    HelpBlock(
                        "File operations",
                        "cp src dst", "mv src dst", "rm file", "mkdir dir", "echo text > file"
                    )
                    HelpBlock(
                        "Session",
                        "exit", "command &  (run in background)"
                    )
                    Text(
                        "Forensics exports land in /sdcard/Download/E-Crew/cases.",
                        fontSize = 11.sp,
                        color = MonoGray
                    )
                }
            }
        )
    }

    @Composable
    private fun HelpBlock(title: String, vararg commands: String) {
        Text("$title:", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
        commands.forEach { cmd ->
            Text(cmd, fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = MonoGray)
        }
        Spacer(Modifier.height(8.dp))
    }

