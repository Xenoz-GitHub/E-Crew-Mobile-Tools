package com.ecrew.toolkit.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.activity.compose.BackHandler
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import android.view.View
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner
import com.ecrew.toolkit.gridshock.GameEngine
import com.ecrew.toolkit.gridshock.GridshockAudio
import com.ecrew.toolkit.gridshock.GridshockHaptics
import com.ecrew.toolkit.gridshock.GridshockSettings
import com.ecrew.toolkit.gridshock.GridshockSnapshot
import com.ecrew.toolkit.gridshock.GridshockStore
import com.ecrew.toolkit.gridshock.GridshockView
import com.ecrew.toolkit.gridshock.Mode
import kotlinx.coroutines.delay

private val GameCard = Color(0xFF101820)
private val GameMuted = Color(0xFF8FA3A8)
private val GameInfo = Color(0xFF00E5FF)
private val GameWarn = Color(0xFFF4D03F)

@Composable
fun GamesHubScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val hostView = LocalView.current
    var settings by remember { mutableStateOf(GridshockSettings(true, true, false, false, Mode.CLASSIC)) }
    var bestScores by remember { mutableStateOf(mapOf<Mode, Int>()) }
    var saved by remember { mutableStateOf<GridshockSnapshot?>(null) }
    var playing by remember { mutableStateOf(false) }
    var mode by remember { mutableStateOf(Mode.CLASSIC) }
    var resume by remember { mutableStateOf<GridshockSnapshot?>(null) }

    LaunchedEffect(Unit) {
        val store = GridshockStore(context)
        try {
            settings = store.loadSettings()
            mode = settings.lastMode
            bestScores = Mode.entries.associateWith { store.bestScore(it) }
            saved = store.loadRun()
        } finally {
            store.close()
        }
    }

    if (playing) {
        GridshockGameScreen(
            mode = mode,
            resume = resume,
            settings = settings,
            onSettings = {
                settings = it
                val store = GridshockStore(context)
                try {
                    store.saveSettings(it)
                } finally {
                    store.close()
                }
            },
            onExit = {
                hostView.findFocus()?.clearFocus()
                hostView.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_AUTO
                playing = false
                resume = null
                val store = GridshockStore(context)
                try {
                    saved = store.loadRun()
                    bestScores = Mode.entries.associateWith { store.bestScore(it) }
                } finally {
                    store.close()
                }
            }
        )
    } else {
    Column(
        Modifier.fillMaxSize().padding(12.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("Back", fontSize = 10.sp) }
            Text("Games hub", color = GameInfo, fontSize = 18.sp)
        }
        Card(colors = CardDefaults.cardColors(containerColor = GameCard)) {
            Column(Modifier.padding(12.dp)) {
                Text("GRIDSHOCK", color = GameInfo, fontSize = 22.sp)
                Text(
                    "Cyber block puzzle. 8x8 board, endless run, blind-bag pieces. " +
                        "No game engine and no new permissions.",
                    color = GameMuted,
                    fontSize = 10.sp
                )
                Mode.entries.forEach { candidate ->
                    Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                        Checkbox(
                            checked = mode == candidate,
                            onCheckedChange = { mode = candidate }
                        )
                        Column {
                            Text(candidate.name, fontSize = 11.sp)
                            Text(
                                when (candidate) {
                                    Mode.CLASSIC -> "Standard clear scoring."
                                    Mode.BREACH -> "Corruption and harder clear scoring."
                                    Mode.ZEN -> "No game over; Overload disabled."
                                },
                                fontSize = 8.sp,
                                color = GameMuted
                            )
                        }
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = {
                        hostView.findFocus()?.clearFocus()
                        // Compose 1.5 on API 26 can crash while an accessibility service
                        // walks a tree during AndroidView insertion. Hide semantics until the
                        // native board is attached, then restore accessibility in the screen.
                        hostView.importantForAccessibility =
                            View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
                        resume = null
                        playing = true
                    }) { Text("New run", fontSize = 10.sp) }
                    if (saved != null) {
                        OutlinedButton(onClick = {
                            hostView.findFocus()?.clearFocus()
                            hostView.importantForAccessibility =
                                View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
                            resume = saved
                            mode = saved?.mode ?: mode
                            playing = true
                        }) { Text("Resume saved run", fontSize = 10.sp) }
                    }
                }
                Text(
                    "Best: Classic ${bestScores[Mode.CLASSIC] ?: 0}  " +
                        "Breach ${bestScores[Mode.BREACH] ?: 0}  " +
                        "Zen ${bestScores[Mode.ZEN] ?: 0}",
                    color = GameMuted,
                    fontSize = 9.sp,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
        }
        Card(colors = CardDefaults.cardColors(containerColor = GameCard)) {
            Column(Modifier.padding(12.dp)) {
                Text("Settings", color = GameInfo, fontSize = 12.sp)
                SettingRow("Sound", settings.sound) {
                    settings = settings.copy(sound = it)
                    persistSettings(context, settings)
                }
                SettingRow("Haptics", settings.haptics) {
                    settings = settings.copy(haptics = it)
                    persistSettings(context, settings)
                }
                SettingRow("Reduce motion", settings.reduceMotion) {
                    settings = settings.copy(reduceMotion = it)
                    persistSettings(context, settings)
                }
                SettingRow("Allow rotation (tap a tray piece)", settings.allowRotation) {
                    settings = settings.copy(allowRotation = it)
                    persistSettings(context, settings)
                }
                Text(
                    "GRIDSHOCK stores scores and a resumable run only in gridshock.db.",
                    color = GameMuted,
                    fontSize = 8.sp
                )
            }
        }
    }
    }
}

@Composable
private fun SettingRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onChange)
        Text(label, fontSize = 10.sp)
    }
}

private fun persistSettings(context: android.content.Context, settings: GridshockSettings) {
    val store = GridshockStore(context)
    try {
        store.saveSettings(settings)
    } finally {
        store.close()
    }
}

@Composable
private fun GridshockGameScreen(
    mode: Mode,
    resume: GridshockSnapshot?,
    settings: GridshockSettings,
    onSettings: (GridshockSettings) -> Unit,
    onExit: () -> Unit
) {
    val context = LocalContext.current
    val hostView = LocalView.current
    val lifecycleOwner = context as? LifecycleOwner
    val engineSeed = resume?.seed ?: System.currentTimeMillis()
    val engineMode = resume?.mode ?: mode
    val engine = remember(engineMode, engineSeed) {
        GameEngine(engineSeed, engineMode, settings.allowRotation)
    }
    val audio = remember { GridshockAudio(context) }
    val haptics = remember { GridshockHaptics() }
    var gameOver by remember { mutableStateOf<GameEngine?>(null) }
    var tick by remember { mutableIntStateOf(0) }
    var audioReady by remember { mutableStateOf(audio.ready || !settings.sound) }
    val view = remember {
        GridshockView(context).also { it.start(engine, settings, audio, haptics, resume) }
    }

    BackHandler {
        hostView.findFocus()?.clearFocus()
        hostView.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_AUTO
        view.saveRun()
        onExit()
    }

    DisposableEffect(Unit) {
        audio.setMuted(!settings.sound)
        haptics.enabled = settings.haptics
        view.onChanged = { tick++ }
        view.onGameOver = { ended ->
            val store = GridshockStore(context)
            try {
                store.recordScore(ended)
                store.clearRun()
            } finally {
                store.close()
            }
            gameOver = ended
        }
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_PAUSE) view.saveRun()
        }
        lifecycleOwner?.lifecycle?.addObserver(observer)
        onDispose {
            lifecycleOwner?.lifecycle?.removeObserver(observer)
            hostView.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_AUTO
            view.saveRun()
            view.onChanged = null
            view.onGameOver = null
            audio.release()
        }
    }

    LaunchedEffect(settings.sound) {
        audioReady = audio.ready || !settings.sound
        while (!audioReady && settings.sound) {
            delay(100)
            audioReady = audio.ready
        }
    }

    LaunchedEffect(Unit) {
        // Restore semantics after the AndroidView has been attached. Keeping semantics
        // hidden is a workaround for a Compose 1.5 API 26 accessibility interop crash.
        delay(750)
        hostView.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_AUTO
        view.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_AUTO
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            TextButton(onClick = {
                hostView.findFocus()?.clearFocus()
                hostView.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_AUTO
                view.saveRun()
                onExit()
            }) { Text("Exit", fontSize = 9.sp) }
            TextButton(onClick = { view.overload() }) {
                Text("Overload", fontSize = 9.sp, color = GameWarn)
            }
            if (settings.allowRotation) {
                TextButton(onClick = { view.rotateFirstTray() }) {
                    Text("Rotate", fontSize = 9.sp)
                }
            }
            TextButton(onClick = {
                audio.setMuted(!settings.sound)
                val next = settings.copy(sound = !settings.sound)
                onSettings(next)
            }) { Text(if (settings.sound) "Mute" else "Unmute", fontSize = 9.sp) }
        }
        AndroidView(
            factory = {
                view.apply {
                    importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                }
            },
            modifier = Modifier.fillMaxSize(),
            update = { current ->
                current.updateSettings(settings)
                current.isEnabled = audioReady || !settings.sound
                current.invalidate()
            }
        )
        if (!audioReady && settings.sound) {
            Text(
                "Calibrating audio...",
                color = GameMuted,
                fontSize = 9.sp,
                modifier = Modifier.padding(6.dp)
            )
        }
    }

    gameOver?.let { ended ->
        AlertDialog(
            onDismissRequest = {
                hostView.findFocus()?.clearFocus()
                gameOver = null
                onExit()
            },
            title = { Text("Run over") },
            text = {
                Text(
                    "Score ${ended.score}\nMoves ${ended.moves}\nLines ${ended.lines}\n" +
                        "Best combo x${ended.bestCombo}\nSeed ${ended.seed}"
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    hostView.findFocus()?.clearFocus()
                    gameOver = null
                    onExit()
                }) { Text("Hub") }
            },
            dismissButton = null
        )
    }
}
