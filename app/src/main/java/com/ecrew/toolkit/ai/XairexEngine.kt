package com.ecrew.toolkit.ai

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Streaming events of one generation ("Generation" is the design-note term for a reply). */
sealed interface XairexEvent {
    data class Token(val text: String) : XairexEvent
    data class Finished(val tokens: Int, val elapsedMs: Long) : XairexEvent
    data class Failed(val message: String) : XairexEvent
}

sealed interface EngineState {
    data object Idle : EngineState
    data class Extracting(val progress: Float) : EngineState
    data object Loading : EngineState
    data object Ready : EngineState
    data object Generating : EngineState
    data class Error(val message: String) : EngineState
}

/** Native inference seam; JVM tests substitute a fake. */
interface XairexBackend {
    fun load(modelPath: String, nCtx: Int, nThreads: Int): Boolean
    fun isLoaded(): Boolean
    fun generate(
        system: String?,
        roles: Array<String>,
        contents: Array<String>,
        maxTokens: Int,
        temperature: Float,
        topP: Float,
        topK: Int,
        seed: Long,
        onToken: (String) -> Boolean
    ): Int

    fun stop()
    fun unload()
    fun version(): String
}

/**
 * Xairex engine client (design note: "Engine client"): process-wide singleton, loads the
 * model lazily on first open of the assistant thread and unloads on close so RAM returns
 * to baseline. One generation at a time; cancellable via [stop].
 */
class XairexEngine internal constructor(private val backend: XairexBackend) {

    private val mutableState = MutableStateFlow<EngineState>(EngineState.Idle)
    val state: StateFlow<EngineState> = mutableState.asStateFlow()

    private val mutex = Mutex()
    private val shutdownScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    private var stopRequested = false

    /** Extracts the bundled model on first use, then loads it. Idempotent. */
    suspend fun ensureReady(context: Context) {
        mutex.withLock {
            if (backend.isLoaded()) {
                mutableState.value = EngineState.Ready
                return
            }
            try {
                val model = withContext(Dispatchers.IO) {
                    AiModelAssets.ensureExtracted(context) { progress ->
                        mutableState.value = EngineState.Extracting(progress)
                    }
                }
                mutableState.value = EngineState.Loading
                val ok = withContext(Dispatchers.IO) {
                    backend.load(model.absolutePath, CONTEXT_TOKENS, threadCount())
                }
                mutableState.value = if (ok) {
                    EngineState.Ready
                } else {
                    EngineState.Error("The model could not be loaded on this device.")
                }
            } catch (t: Throwable) {
                mutableState.value =
                    EngineState.Error(t.message ?: "The model could not be prepared.")
            }
        }
    }

    /** Runs one generation; serialized against [ensureReady] and other generations. */
    fun generate(
        prompt: List<XairexPrompt.Msg>,
        maxTokens: Int = DEFAULT_MAX_TOKENS,
        temperature: Float = 0.7f,
        topP: Float = 0.9f,
        topK: Int = 40,
        seed: Long = -1L
    ): Flow<XairexEvent> = channelFlow {
        mutex.withLock {
            if (!backend.isLoaded()) {
                trySend(XairexEvent.Failed("The model is not available."))
                return@withLock
            }
            stopRequested = false
            mutableState.value = EngineState.Generating
            val startedAt = System.currentTimeMillis()
            val roles = prompt.map { it.role }.toTypedArray()
            val contents = prompt.map { it.content }.toTypedArray()
            val generated = withContext(Dispatchers.IO) {
                backend.generate(
                    XairexPrompt.SYSTEM_PROMPT, roles, contents,
                    maxTokens, temperature, topP, topK, seed
                ) { piece ->
                    trySend(XairexEvent.Token(piece))
                    !stopRequested
                }
            }
            val elapsed = System.currentTimeMillis() - startedAt
            mutableState.value = EngineState.Ready
            if (generated >= 0) {
                trySend(XairexEvent.Finished(generated, elapsed))
            } else {
                trySend(XairexEvent.Failed("Generation failed."))
            }
        }
    }.buffer(Channel.UNLIMITED)

    /** Requests a prompt stop of the running generation (checked per token). */
    fun stop() {
        stopRequested = true
        backend.stop()
    }

    /** Non-blocking teardown for onDispose; waits out an in-flight generation first. */
    fun requestUnload() {
        shutdownScope.launch { shutdown() }
    }

    suspend fun shutdown() {
        mutex.withLock {
            stopRequested = true
            backend.stop()
            if (backend.isLoaded()) backend.unload()
            mutableState.value = EngineState.Idle
        }
    }

    /** Engine build label for the About dialog (never throws). */
    fun engineLabel(): String =
        runCatching { backend.version() }.getOrDefault("llama.cpp")

    private fun threadCount(): Int =
        Runtime.getRuntime().availableProcessors().coerceIn(1, 4)

    companion object {
        const val CONTEXT_TOKENS = 2048
        const val DEFAULT_MAX_TOKENS = 256

        @Volatile
        private var instance: XairexEngine? = null

        /** Process-wide singleton shared by the UI (one loaded model at a time). */
        fun get(): XairexEngine {
            instance?.let { return it }
            return synchronized(this) {
                instance ?: XairexEngine(LlamaNativeBackend()).also { instance = it }
            }
        }
    }
}
