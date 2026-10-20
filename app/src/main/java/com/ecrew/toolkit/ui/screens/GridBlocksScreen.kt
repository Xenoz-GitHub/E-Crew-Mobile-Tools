package com.ecrew.toolkit.ui.screens

import android.view.View
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.EmojiEvents
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.SportsEsports
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner
import com.ecrew.toolkit.games.GamePack
import com.ecrew.toolkit.games.GamePackInstaller
import com.ecrew.toolkit.games.GamePacks
import com.ecrew.toolkit.gridblocks.GameEngine
import com.ecrew.toolkit.gridblocks.GridBlocksAudio
import com.ecrew.toolkit.gridblocks.GridBlocksHaptics
import com.ecrew.toolkit.gridblocks.GridBlocksSettings
import com.ecrew.toolkit.gridblocks.GridBlocksSnapshot
import com.ecrew.toolkit.gridblocks.GridBlocksStore
import com.ecrew.toolkit.gridblocks.GridBlocksView
import com.ecrew.toolkit.gridblocks.Mode
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val GameBg = Color(0xFF060A12)
private val GameCard = Color(0xFF0D1925)
private val GamePanel = Color(0xFF101F2D)
private val GameMuted = Color(0xFF8FA3A8)
private val GameInfo = Color(0xFF55E6FF)
private val GamePink = Color(0xFFFF70C8)
private val GameGreen = Color(0xFF6FE7A5)
private val GameWarn = Color(0xFFFFCB5C)

private data class GameEntry(
    val id: String,
    val title: String,
    val tagline: String,
    val description: String,
    val accent: Color,
    val pack: GamePack? = null
)

private val GameCatalog = listOf(
    GameEntry(
        id = "gridblocks",
        title = "GRIDBLOCKS",
        tagline = "8 × 8 block puzzle",
        description = "Stack glossy blocks, clear lines, chain combos, and keep the grid alive.",
        accent = GameInfo
    ),
    GameEntry(
        id = "mobile-legacy",
        title = "MOBILE LEGACY",
        tagline = "Brawl arena",
        description = "A fast arena brawler. Install it once from the Hub, then launch it right here.",
        accent = GameWarn,
        pack = GamePacks.MobileLegacy
    ),
    GameEntry(
        id = "swords-ninja",
        title = "SWORDS NINJA",
        tagline = "2D ninja fighter",
        description = "A high-energy fighter. Install it once from the Hub, then launch it right here.",
        accent = GamePink,
        pack = GamePacks.SwordsNinja
    )
)

@Composable
fun GamesHubScreen(onBack: () -> Unit) {
    var openedGame by rememberSaveable { mutableStateOf<String?>(null) }
    if (openedGame == "gridblocks") {
        GridBlocksLobby(onBack = { openedGame = null })
    } else {
        GamesHubLobby(onBack = onBack, onOpen = { openedGame = it })
    }
}

@Composable
private fun GamesHubLobby(onBack: () -> Unit, onOpen: (String) -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    var installedIds by remember { mutableStateOf<Set<String>>(emptySet()) }
    var installingId by remember { mutableStateOf<String?>(null) }
    var permissionGame by remember { mutableStateOf<GameEntry?>(null) }
    var pendingImportId by rememberSaveable { mutableStateOf<String?>(null) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    fun isBundled(game: GameEntry): Boolean =
        game.pack?.let { GamePackInstaller.isBundled(context, it) } == true

    fun refreshInstalled() {
        installedIds = GameCatalog.mapNotNull { game ->
            game.pack?.takeIf { GamePackInstaller.isInstalled(context, it) }?.id
        }.toSet()
    }

    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) refreshInstalled()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    LaunchedEffect(Unit) { refreshInstalled() }

    val apkPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val game = pendingImportId?.let { id -> GameCatalog.firstOrNull { it.id == id } }
        pendingImportId = null
        val pack = game?.pack
        if (game == null || pack == null || uri == null) return@rememberLauncherForActivityResult

        installingId = game.id
        scope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    val staging = File(context.cacheDir, "imported-packs/${pack.id}.apk")
                    staging.parentFile?.mkdirs()
                    try {
                        context.contentResolver.openInputStream(uri)?.use { input ->
                            staging.outputStream().use { output ->
                                input.copyTo(output, 1024 * 1024)
                            }
                        } ?: throw IllegalStateException("The selected file could not be read.")

                        @Suppress("DEPRECATION")
                        val info = context.packageManager.getPackageArchiveInfo(staging.absolutePath, 0)
                        if (info?.packageName != pack.packageName) {
                            throw IllegalArgumentException(
                                "That file is ${info?.packageName ?: "not a readable APK"}, not ${game.title}."
                            )
                        }

                        staging.inputStream().use { input ->
                            GamePackInstaller.installStream(context, pack, input)
                        }
                    } finally {
                        staging.delete()
                    }
                }
            }
            installingId = null
            if (outcome.isFailure) {
                errorMessage = "Could not import ${game.title}: " +
                    (outcome.exceptionOrNull()?.message ?: "unknown error")
            }
        }
    }

    fun beginImport(game: GameEntry) {
        if (installingId != null) return
        pendingImportId = game.id
        runCatching {
            apkPicker.launch(arrayOf("application/vnd.android.package-archive", "*/*"))
        }.onFailure {
            pendingImportId = null
            errorMessage = "No file picker is available to choose the ${game.title} APK."
        }
    }

    fun startPack(game: GameEntry) {
        val pack = game.pack ?: return
        if (installingId != null) return
        if (GamePackInstaller.isInstalled(context, pack)) {
            if (!GamePackInstaller.launch(context, pack)) {
                errorMessage = "${game.title} is installed but could not be opened."
            }
            return
        }
        if (!GamePackInstaller.supportsNativeAbi(pack)) {
            errorMessage = "${game.title} requires 32-bit ARM support, which this device does not expose."
            return
        }
        if (!GamePackInstaller.canInstall(context)) {
            permissionGame = game
            return
        }

        if (!isBundled(game)) {
            beginImport(game)
            return
        }

        installingId = game.id
        scope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { GamePackInstaller.installBundled(context, pack) }
            }
            installingId = null
            if (outcome.isFailure) {
                errorMessage = "Could not prepare ${game.title}: " +
                    (outcome.exceptionOrNull()?.message ?: "unknown error")
            }
        }
    }

    fun openGame(game: GameEntry) {
        if (game.pack == null) onOpen(game.id) else startPack(game)
    }

    BackHandler(onBack = onBack)
    Column(
        Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    listOf(Color(0xFF050811), Color(0xFF091725), Color(0xFF05070D))
                )
            )
            .verticalScroll(rememberScrollState())
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) {
                Icon(Icons.Default.ArrowBack, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(4.dp))
                Text("Back", fontSize = 10.sp)
            }
            Spacer(Modifier.weight(1f))
            Text("GAME LAUNCHER", color = GameMuted, fontSize = 9.sp, letterSpacing = 1.2.sp)
        }
        Text(
            "GAMES HUB",
            color = Color.White,
            fontWeight = FontWeight.Bold,
            fontSize = 28.sp,
            letterSpacing = 1.4.sp
        )
        Text(
            "Choose a world. GridBlocks is built in; pack games install once through Android and launch right here.",
            color = GameMuted,
            fontSize = 11.sp
        )
        Spacer(Modifier.height(2.dp))
        Card(
            Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF0A202D)),
            border = BorderStroke(1.dp, Color(0x3355E6FF)),
            shape = RoundedCornerShape(18.dp)
        ) {
            Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Default.SportsEsports,
                    contentDescription = null,
                    tint = GameInfo,
                    modifier = Modifier.size(34.dp)
                )
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text("ONE HUB, MORE WORLDS", color = GameInfo, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    val readyCount = GameCatalog.count { it.pack == null || isBundled(it) }
                    Text(
                        if (readyCount > 1) {
                            "$readyCount games are ready in this build. First play installs once through Android."
                        } else {
                            "GridBlocks is ready. If a game is not bundled, choose your own APK file once and it installs here."
                        },
                        color = GameMuted,
                        fontSize = 10.sp
                    )
                }
            }
        }
        Text("CHOOSE A GAME", color = GameMuted, fontSize = 9.sp, letterSpacing = 1.2.sp)
        GameCatalog.forEach { game ->
            val installed = game.pack?.let { installedIds.contains(it.id) } == true
            GameTile(
                game = game,
                installed = installed,
                installing = installingId == game.id,
                bundled = isBundled(game),
                supported = game.pack?.let { GamePackInstaller.supportsNativeAbi(it) } != false,
                onClick = { openGame(game) }
            )
        }
        Text(
            "Bundled games install with one tap. If a game is not bundled, pick its APK file once: Android installs it, it stays in your app list, and it always launches from here.",
            color = GameMuted,
            fontSize = 9.sp,
            modifier = Modifier.padding(horizontal = 2.dp, vertical = 4.dp)
        )
    }

    permissionGame?.let { game ->
        AlertDialog(
            onDismissRequest = { permissionGame = null },
            title = { Text("Allow game pack installs") },
            text = {
                Text(
                    "Android requires your permission before ${game.title} can be installed. " +
                        "Enable installs for E-Crew Toolkit, then return to the Hub and tap Install."
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        permissionGame = null
                        GamePackInstaller.openInstallPermissionSettings(context)
                    }
                ) { Text("Open settings") }
            },
            dismissButton = {
                TextButton(onClick = { permissionGame = null }) { Text("Not now") }
            }
        )
    }

    installingId?.let { id ->
        val title = GameCatalog.firstOrNull { it.id == id }?.title ?: "Game pack"
        AlertDialog(
            onDismissRequest = {},
            title = { Text("Preparing $title") },
            text = { Text("Copying the pack into Android's installer. This can take a moment.") },
            confirmButton = {}
        )
    }

    errorMessage?.let { message ->
        AlertDialog(
            onDismissRequest = { errorMessage = null },
            title = { Text("Game pack") },
            text = { Text(message) },
            confirmButton = {
                TextButton(onClick = { errorMessage = null }) { Text("Close") }
            }
        )
    }
}

@Composable
private fun GameTile(
    game: GameEntry,
    installed: Boolean,
    installing: Boolean,
    bundled: Boolean,
    supported: Boolean,
    onClick: () -> Unit
) {
    val builtIn = game.pack == null
    val status = when {
        !supported -> "NEEDS 32-BIT ARM"
        installing -> "PREPARING INSTALL"
        builtIn -> "READY • BUILT IN"
        installed -> "INSTALLED • TAP TO PLAY"
        bundled -> "INSTALL ONCE • INCLUDED"
        else -> "NOT BUNDLED • IMPORT YOUR APK"
    }
    val action = when {
        !supported -> "N/A"
        installing -> "Wait"
        builtIn || installed -> "Play"
        bundled -> "Install"
        else -> "Import"
    }
    val statusColor = when {
        !supported || installing -> GameMuted
        builtIn || installed -> GameGreen
        bundled -> GameMuted
        else -> game.accent
    }

    Card(
        Modifier
            .fillMaxWidth()
            .clickable(enabled = !installing && supported, onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = GameCard),
        border = BorderStroke(1.dp, game.accent.copy(alpha = 0.45f)),
        shape = RoundedCornerShape(16.dp)
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .size(78.dp)
                    .background(
                        Brush.linearGradient(
                            listOf(game.accent.copy(alpha = 0.24f), Color(0xFF070D14))
                        ),
                        RoundedCornerShape(13.dp)
                    ),
                contentAlignment = Alignment.Center
            ) {
                GameEmblem(game)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(game.title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Text(game.tagline, color = game.accent, fontSize = 10.sp)
                Text(game.description, color = GameMuted, fontSize = 9.sp, modifier = Modifier.padding(top = 3.dp))
                Text(
                    status,
                    color = statusColor,
                    fontSize = 8.sp,
                    letterSpacing = 1.sp,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
            Button(
                onClick = onClick,
                enabled = !installing && supported,
                contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 11.dp, vertical = 6.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (builtIn || installed) GameGreen else game.accent,
                    contentColor = Color(0xFF041018)
                )
            ) {
                if (!installing) {
                    Icon(Icons.Default.PlayArrow, contentDescription = null, modifier = Modifier.size(15.dp))
                    Spacer(Modifier.width(2.dp))
                }
                Text(action, fontSize = 10.sp, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun GameEmblem(game: GameEntry) {
    if (game.pack == null) {
        MiniBlockPreview()
        return
    }
    val initials = game.title
        .split(' ')
        .mapNotNull { it.firstOrNull()?.toString() }
        .take(2)
        .joinToString("")
    Box(Modifier.size(58.dp), contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            drawCircle(
                brush = Brush.radialGradient(
                    listOf(game.accent.copy(alpha = 0.42f), Color.Transparent)
                ),
                radius = size.minDimension * 0.56f
            )
            drawCircle(
                color = game.accent.copy(alpha = 0.7f),
                radius = size.minDimension * 0.43f,
                style = Stroke(width = 1.4.dp.toPx())
            )
        }
        Text(
            initials,
            color = game.accent,
            fontSize = 19.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.sp
        )
    }
}

@Composable
private fun MiniBlockPreview() {
    Canvas(Modifier.size(58.dp)) {
        val cell = size.minDimension / 6.3f
        val originX = (size.width - cell * 2.1f) / 2f
        val originY = (size.height - cell * 2.1f) / 2f
        val colors = listOf(GameInfo, GamePink, GameWarn, GameGreen)
        for (index in 0 until 4) {
            val col = index % 2
            val row = index / 2
            drawRoundRect(
                brush = Brush.linearGradient(
                    listOf(colors[index], colors[index].copy(alpha = 0.55f))
                ),
                topLeft = Offset(originX + col * cell * 1.05f, originY + row * cell * 1.05f),
                size = Size(cell, cell),
                cornerRadius = CornerRadius(cell * 0.18f),
            )
            drawRoundRect(
                color = Color.White.copy(alpha = 0.35f),
                topLeft = Offset(originX + col * cell * 1.05f + cell * 0.12f, originY + row * cell * 1.05f + cell * 0.1f),
                size = Size(cell * 0.7f, cell * 0.12f),
                cornerRadius = CornerRadius(cell * 0.06f)
            )
        }
    }
}

@Composable
private fun GridBlocksLobby(onBack: () -> Unit) {
    val context = LocalContext.current
    val hostView = LocalView.current
    var settings by remember { mutableStateOf(GridBlocksSettings(true, true, false, false, Mode.CLASSIC)) }
    var bestScores by remember { mutableStateOf(mapOf<Mode, Int>()) }
    var saved by remember { mutableStateOf<GridBlocksSnapshot?>(null) }
    var playing by remember { mutableStateOf(false) }
    var mode by remember { mutableStateOf(Mode.CLASSIC) }
    var resume by remember { mutableStateOf<GridBlocksSnapshot?>(null) }

    LaunchedEffect(Unit) {
        try {
            val store = GridBlocksStore(context)
            try {
                settings = store.loadSettings()
                mode = settings.lastMode
                bestScores = Mode.entries.associateWith { store.bestScore(it) }
                saved = store.loadRun()
            } finally {
                store.close()
            }
        } catch (_: Exception) {
            // A damaged or unavailable local store must not prevent the game from running.
        }
    }

    if (playing) {
        GridBlocksGameScreen(
            mode = mode,
            resume = resume,
            settings = settings,
            onSettings = {
                settings = it
                persistSettings(context, it)
            },
            onExit = {
                hostView.findFocus()?.clearFocus()
                hostView.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_AUTO
                playing = false
                resume = null
                try {
                    val store = GridBlocksStore(context)
                    try {
                        saved = store.loadRun()
                        bestScores = Mode.entries.associateWith { store.bestScore(it) }
                    } finally {
                        store.close()
                    }
                } catch (_: Exception) {
                    // Keep the lobby usable if the local score store cannot be read.
                }
            }
        )
        return
    }

    BackHandler(onBack = onBack)
    Column(
        Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    listOf(Color(0xFF050811), Color(0xFF0A1A27), Color(0xFF05070D))
                )
            )
            .verticalScroll(rememberScrollState())
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) {
                Icon(Icons.Default.ArrowBack, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(4.dp))
                Text("Games", fontSize = 10.sp)
            }
            Spacer(Modifier.weight(1f))
            Text("OFFLINE ARCADE", color = GameMuted, fontSize = 9.sp, letterSpacing = 1.2.sp)
        }
        Card(
            Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF0A202D)),
            border = BorderStroke(1.dp, GameInfo.copy(alpha = 0.45f)),
            shape = RoundedCornerShape(20.dp)
        ) {
            Column(Modifier.padding(16.dp)) {
                Text("GRIDBLOCKS", color = Color.White, fontSize = 26.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.3.sp)
                Text("8 × 8 BLOCK PUZZLE", color = GameInfo, fontSize = 9.sp, letterSpacing = 1.3.sp)
                Spacer(Modifier.height(8.dp))
                Text(
                    "A glossy, high-energy block puzzle. Clear rows and columns, chain combos, " +
                        "and trigger Overload when the grid fills up.",
                    color = GameMuted,
                    fontSize = 10.sp
                )
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatChip("BEST", "${bestScores.values.maxOrNull() ?: 0}", GameWarn)
                    StatChip("MODES", "${Mode.entries.size}", GameInfo)
                    StatChip("BOARD", "8 × 8", GameGreen)
                }
            }
        }

        Text("SELECT A MODE", color = GameMuted, fontSize = 9.sp, letterSpacing = 1.2.sp)
        Mode.entries.forEach { candidate ->
            ModeCard(
                mode = candidate,
                selected = mode == candidate,
                best = bestScores[candidate] ?: 0,
                onClick = {
                    mode = candidate
                    val store = GridBlocksStore(context)
                    try {
                        store.saveSettings(settings.copy(lastMode = candidate))
                    } finally {
                        store.close()
                    }
                    settings = settings.copy(lastMode = candidate)
                }
            )
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    hostView.findFocus()?.clearFocus()
                    // Compose 1.5 on API 26 can crash while an accessibility service
                    // walks a tree during AndroidView insertion. Hide semantics until the
                    // native board is attached, then restore accessibility in the screen.
                    hostView.importantForAccessibility =
                        View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
                    resume = null
                    playing = true
                },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = GameInfo, contentColor = Color(0xFF041018))
            ) {
                Icon(Icons.Default.PlayArrow, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(4.dp))
                Text("Start run", fontSize = 11.sp, fontWeight = FontWeight.Bold)
            }
            if (saved != null) {
                OutlinedButton(
                    onClick = {
                        hostView.findFocus()?.clearFocus()
                        hostView.importantForAccessibility =
                            View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
                        resume = saved
                        mode = saved?.mode ?: mode
                        playing = true
                    },
                    modifier = Modifier.weight(1f),
                    border = BorderStroke(1.dp, GameInfo.copy(alpha = 0.55f))
                ) {
                    Text("Resume", fontSize = 11.sp)
                }
            }
        }
        if (saved != null) {
            Text(
                "Saved run: ${saved?.mode?.name} · score ${saved?.score} · move ${saved?.moves}",
                color = GameMuted,
                fontSize = 9.sp
            )
        }

        Card(
            Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = GameCard),
            border = BorderStroke(1.dp, Color.White.copy(alpha = 0.07f)),
            shape = RoundedCornerShape(16.dp)
        ) {
            Column(Modifier.padding(12.dp)) {
                Text("SETTINGS", color = GameInfo, fontSize = 10.sp, letterSpacing = 1.1.sp)
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
                SettingRow("Allow piece rotation", settings.allowRotation) {
                    settings = settings.copy(allowRotation = it)
                    persistSettings(context, settings)
                }
                Text(
                    "Scores and resumable runs stay in the local GridBlocks database.",
                    color = GameMuted,
                    fontSize = 8.sp,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
        }

        Card(
            Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF0B141D)),
            border = BorderStroke(1.dp, Color.White.copy(alpha = 0.05f)),
            shape = RoundedCornerShape(14.dp)
        ) {
            Column(Modifier.padding(12.dp)) {
                Text("HOW TO PLAY", color = GameWarn, fontSize = 10.sp, letterSpacing = 1.1.sp)
                Text(
                    "Drag a piece from the tray. The piece floats above your finger so the " +
                        "target cells stay visible. Fill a full row or column to clear it. " +
                        "Build combos and use Overload when the meter is full.",
                    color = GameMuted,
                    fontSize = 9.sp,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
        }
    }
}

@Composable
private fun StatChip(label: String, value: String, accent: Color) {
    Column(
        Modifier
            .background(Color(0xFF07131D), RoundedCornerShape(10.dp))
            .padding(horizontal = 10.dp, vertical = 7.dp)
    ) {
        Text(label, color = GameMuted, fontSize = 7.sp, letterSpacing = 1.sp)
        Text(value, color = accent, fontSize = 13.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun ModeCard(mode: Mode, selected: Boolean, best: Int, onClick: () -> Unit) {
    val accent = when (mode) {
        Mode.CLASSIC -> GameInfo
        Mode.BREACH -> GamePink
        Mode.ZEN -> GameGreen
    }
    Card(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = if (selected) accent.copy(alpha = 0.12f) else GameCard
        ),
        border = BorderStroke(1.dp, if (selected) accent.copy(alpha = 0.7f) else Color.White.copy(alpha = 0.06f)),
        shape = RoundedCornerShape(14.dp)
    ) {
        Row(Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .size(16.dp)
                    .background(if (selected) accent else Color.Transparent, CircleShape)
                    .clickable(onClick = onClick),
                contentAlignment = Alignment.Center
            ) {
                if (selected) {
                    Box(Modifier.size(6.dp).background(Color(0xFF041018), CircleShape))
                }
            }
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(mode.name, color = if (selected) Color.White else GameMuted, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                Text(
                    when (mode) {
                        Mode.CLASSIC -> "Standard clears and scoring."
                        Mode.BREACH -> "Corruption cells and harder clear payouts."
                        Mode.ZEN -> "No game over; Overload is disabled."
                    },
                    color = GameMuted,
                    fontSize = 8.sp
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                Icon(Icons.Default.EmojiEvents, contentDescription = null, tint = accent.copy(alpha = 0.8f), modifier = Modifier.size(13.dp))
                Text("$best", color = accent, fontSize = 11.sp, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun SettingRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, fontSize = 10.sp, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

private fun persistSettings(context: android.content.Context, settings: GridBlocksSettings) {
    try {
        val store = GridBlocksStore(context)
        try {
            store.saveSettings(settings)
        } finally {
            store.close()
        }
    } catch (_: Exception) {
        // Settings are a convenience; the current in-memory values still apply.
    }
}

@Composable
private fun GridBlocksGameScreen(
    mode: Mode,
    resume: GridBlocksSnapshot?,
    settings: GridBlocksSettings,
    onSettings: (GridBlocksSettings) -> Unit,
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
    val audio = remember { GridBlocksAudio(context) }
    val haptics = remember { GridBlocksHaptics() }
    var gameOver by remember { mutableStateOf<GameEngine?>(null) }
    var audioReady by remember { mutableStateOf(audio.ready || !settings.sound) }
    val view = remember {
        GridBlocksView(context).also { it.start(engine, settings, audio, haptics, resume) }
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
        view.onGameOver = { ended ->
            try {
                val store = GridBlocksStore(context)
                try {
                    store.recordScore(ended)
                    store.clearRun()
                } finally {
                    store.close()
                }
            } catch (_: Exception) {
                // The run-over dialog must still appear if score persistence fails.
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

    Column(Modifier.fillMaxSize().background(GameBg)) {
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
                }) { Text("Back to lobby") }
            },
            dismissButton = null
        )
    }
}
