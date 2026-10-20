package com.ecrew.protocol

/**
 * Protocol-wide constants and message builders/accessors for protocol v1.
 * See notes/2026-10-19-0513-remote-support-design.md, section 4 (message table).
 */
object ProtocolConstants {
    const val VERSION = "1.0"

    /** Fixed RFCOMM service UUID (obscurity only; AES-GCM is the security boundary). */
    const val BT_SERVICE_UUID = "8ce255c0-200a-11e0-ac64-0800200c9a66"

    /** mDNS service type used for LAN discovery. */
    const val MDNS_SERVICE_TYPE = "_ecrew-remote._tcp"

    /** Hard cap for any single wire frame (JSON, base64 JPEG, or sealed frame). */
    const val MAX_FRAME_BYTES = 4 * 1024 * 1024

    /** Hard cap for plaintext handshake frames. */
    const val MAX_HANDSHAKE_BYTES = 64 * 1024

    /** Handshake: max failed code attempts before the code is burned. */
    const val MAX_ATTEMPTS = 3

    /** Handshake: minimum delay between counted attempts. */
    const val RATE_LIMIT_MS = 2000L

    /** Keepalive interval; session dropped after 3 missed pongs. */
    const val PING_INTERVAL_MS = 5000L
    const val MAX_MISSED_PONGS = 3

    /** Agent capture parameters. */
    const val CAPTURE_MAX_FPS = 8
    const val JPEG_QUALITY = 55
    const val MAX_STREAM_EDGE = 1024
}

/** Message type tags (`t` field). */
object Msg {
    const val HELLO = "hello"
    const val AUTH_OK = "auth_ok"
    const val AUTH_FAIL = "auth_fail"
    const val SCREEN_FRAME = "screen_frame"
    const val STREAM_START = "stream_start"
    const val STREAM_STOP = "stream_stop"
    const val TAP = "tap"
    const val SWIPE = "swipe"
    const val GLOBAL_ACTION = "global_action"
    const val TEXT_INPUT = "text_input"
    const val PING = "ping"
    const val PONG = "pong"
    const val SESSION_END = "session_end"
    const val AUDIT_MARKER = "audit_marker"

    /** Additive v1 extension: controller asks for (and agent returns) the app inventory. */
    const val APP_LIST_REQ = "app_list_req"
    const val APP_LIST = "app_list"
}

/** Global action values accepted by [Messages.globalAction]. */
object GlobalActions {
    const val BACK = "back"
    const val HOME = "home"
    const val RECENTS = "recents"
    const val NOTIFICATIONS = "notifications"

    val ALL = setOf(BACK, HOME, RECENTS, NOTIFICATIONS)
}

object Messages {

    fun type(message: Map<String, Any?>): String? = message["t"] as? String

    // ---------------------------------------------------------------- builders

    fun hello(code: String, saltB64: String, model: String?, ver: String, ts: Long): Map<String, Any?> =
        mapOf("t" to Msg.HELLO, "code" to code, "salt" to saltB64, "model" to model, "ver" to ver, "ts" to ts)

    fun authOk(sessionId: String): Map<String, Any?> = mapOf("t" to Msg.AUTH_OK, "sessionId" to sessionId)

    fun authFail(reason: String): Map<String, Any?> = mapOf("t" to Msg.AUTH_FAIL, "reason" to reason)

    fun screenFrame(jpegB64: String, w: Long, h: Long, ts: Long): Map<String, Any?> =
        mapOf("t" to Msg.SCREEN_FRAME, "jpeg" to jpegB64, "w" to w, "h" to h, "ts" to ts)

    fun streamStart(): Map<String, Any?> = mapOf("t" to Msg.STREAM_START)

    fun streamStop(): Map<String, Any?> = mapOf("t" to Msg.STREAM_STOP)

    fun tap(x: Double, y: Double): Map<String, Any?> = mapOf("t" to Msg.TAP, "x" to x, "y" to y)

    fun swipe(x1: Double, y1: Double, x2: Double, y2: Double, durationMs: Long): Map<String, Any?> =
        mapOf("t" to Msg.SWIPE, "x1" to x1, "y1" to y1, "x2" to x2, "y2" to y2, "durationMs" to durationMs)

    fun globalAction(action: String): Map<String, Any?> {
        require(action in GlobalActions.ALL) { "unsupported global action: $action" }
        return mapOf("t" to Msg.GLOBAL_ACTION, "action" to action)
    }

    fun textInput(text: String): Map<String, Any?> = mapOf("t" to Msg.TEXT_INPUT, "text" to text)

    fun ping(ts: Long): Map<String, Any?> = mapOf("t" to Msg.PING, "ts" to ts)

    fun pong(ts: Long): Map<String, Any?> = mapOf("t" to Msg.PONG, "ts" to ts)

    fun sessionEnd(reason: String): Map<String, Any?> = mapOf("t" to Msg.SESSION_END, "reason" to reason)

    fun auditMarker(note: String): Map<String, Any?> = mapOf("t" to Msg.AUDIT_MARKER, "note" to note)

    /** Request the agent's installed-app inventory; only honored inside an active session. */
    fun appListRequest(): Map<String, Any?> = mapOf("t" to Msg.APP_LIST_REQ)

    // ---------------------------------------------------------------- accessors

    fun string(message: Map<String, Any?>, key: String): String? = message[key] as? String

    fun long(message: Map<String, Any?>, key: String): Long? = (message[key] as? Number)?.toLong()

    fun int(message: Map<String, Any?>, key: String): Int? = (message[key] as? Number)?.toInt()

    fun double(message: Map<String, Any?>, key: String): Double? = (message[key] as? Number)?.toDouble()
}
