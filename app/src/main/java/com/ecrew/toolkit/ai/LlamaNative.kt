package com.ecrew.toolkit.ai

/**
 * JNI surface of libecrew-llm.so (see llm/src/main/cpp/jni.cpp). Strings cross the
 * boundary as UTF-8 byte arrays so emoji and other non-BMP characters survive modified
 * UTF-8; paths and roles are plain JNI strings.
 */
object LlamaNative {
    init {
        System.loadLibrary("ecrew-llm")
    }

    fun interface TokenCallback {
        /** Returns false to stop generation after this piece. */
        fun onToken(piece: ByteArray): Boolean
    }

    external fun nativeVersion(): String

    /** Returns a non-zero native handle, or 0 on failure. */
    external fun nativeLoad(modelPath: String, nCtx: Int, nThreads: Int): Long

    /** Blocking generation; returns generated token count or -1 on failure. */
    external fun nativeGenerate(
        handle: Long,
        system: String?,
        roles: Array<String>,
        contents: Array<ByteArray>,
        maxTokens: Int,
        temperature: Float,
        topP: Float,
        topK: Int,
        seed: Long,
        callback: TokenCallback
    ): Int

    external fun nativeStop(handle: Long)
    external fun nativeFree(handle: Long)
}

/** [XairexBackend] backed by the native llama.cpp build. */
class LlamaNativeBackend : XairexBackend {

    @Volatile
    private var handle = 0L

    override fun load(modelPath: String, nCtx: Int, nThreads: Int): Boolean {
        if (handle != 0L) return true
        val h = LlamaNative.nativeLoad(modelPath, nCtx, nThreads)
        handle = h
        return h != 0L
    }

    override fun isLoaded(): Boolean = handle != 0L

    override fun generate(
        system: String?,
        roles: Array<String>,
        contents: Array<String>,
        maxTokens: Int,
        temperature: Float,
        topP: Float,
        topK: Int,
        seed: Long,
        onToken: (String) -> Boolean
    ): Int {
        val h = handle
        if (h == 0L) return -1
        val payload = Array(contents.size) { contents[it].toByteArray(Charsets.UTF_8) }
        return LlamaNative.nativeGenerate(
            h, system, roles, payload, maxTokens, temperature, topP, topK, seed
        ) { piece -> onToken(String(piece, Charsets.UTF_8)) }
    }

    override fun stop() {
        val h = handle
        if (h != 0L) LlamaNative.nativeStop(h)
    }

    override fun unload() {
        val h = handle
        if (h != 0L) {
            LlamaNative.nativeFree(h)
            handle = 0L
        }
    }

    override fun version(): String = LlamaNative.nativeVersion()
}
