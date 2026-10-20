package com.ecrew.toolkit.terminal

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.util.Log
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.inputmethod.InputMethodManager
import com.termux.terminal.TerminalEmulator
import com.termux.terminal.TerminalSession
import com.termux.terminal.TerminalSessionClient
import com.termux.view.TerminalView
import com.termux.view.TerminalViewClient

/** Bridges TerminalSession events to the view, clipboard and logcat. */
class SessionClient(private val context: Context) : TerminalSessionClient {

    @Volatile
    var view: TerminalView? = null

    private fun clipboard(): ClipboardManager? =
        context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager

    override fun onTextChanged(session: TerminalSession) {
        view?.post { view?.onScreenUpdated() }
    }

    override fun onTitleChanged(session: TerminalSession) {
        view?.post { view?.invalidate() }
    }

    override fun onSessionFinished(session: TerminalSession) {
        view?.post { view?.onScreenUpdated() }
    }

    override fun onCopyTextToClipboard(session: TerminalSession, text: String) {
        clipboard()?.setPrimaryClip(ClipData.newPlainText("terminal", text))
    }

    override fun onPasteTextFromClipboard(session: TerminalSession) {
        val text = clipboard()?.primaryClip?.let { clip ->
            if (clip.itemCount > 0) clip.getItemAt(0).coerceToText(context).toString() else null
        }
        if (!text.isNullOrEmpty()) {
            val bytes = text.toByteArray(Charsets.UTF_8)
            session.write(bytes, 0, bytes.size)
        }
    }

    override fun onBell(session: TerminalSession) {}
    override fun onColorsChanged(session: TerminalSession) {
        view?.post { view?.invalidate() }
    }

    override fun onTerminalCursorStateChange(visible: Boolean) {}

    override fun getTerminalCursorStyle(): Int =
        TerminalEmulator.DEFAULT_TERMINAL_CURSOR_STYLE

    override fun logError(tag: String, message: String) { Log.e(tag, message) }
    override fun logWarn(tag: String, message: String) { Log.w(tag, message) }
    override fun logInfo(tag: String, message: String) { Log.i(tag, message) }
    override fun logDebug(tag: String, message: String) { Log.d(tag, message) }
    override fun logVerbose(tag: String, message: String) { Log.v(tag, message) }
    override fun logStackTraceWithMessage(tag: String, message: String, e: Exception) {
        Log.e(tag, message, e)
    }

    override fun logStackTrace(tag: String, e: Exception) { Log.e(tag, "exception", e) }
}

/** Minimal TerminalViewClient: keyboard bring-up, sane defaults, logging. */
class ViewClient(private val context: Context, private val view: TerminalView) :
    TerminalViewClient {

    override fun onScale(scale: Float): Float = 1.0f

    override fun onSingleTapUp(e: MotionEvent?) {
        // Tap = focus + bring up the soft keyboard. Focus is also what routes
        // hardware keyboard key events to the terminal view.
        view.requestFocus()
        val imm = context.getSystemService(Context.INPUT_METHOD_SERVICE) as? InputMethodManager
        imm?.showSoftInput(view, InputMethodManager.SHOW_IMPLICIT)
    }

    override fun shouldBackButtonBeMappedToEscape(): Boolean = false
    override fun shouldEnforceCharBasedInput(): Boolean = false
    override fun shouldUseCtrlSpaceWorkaround(): Boolean = false
    override fun isTerminalViewSelected(): Boolean = true
    override fun copyModeChanged(copyMode: Boolean) {}

    override fun onKeyDown(keyCode: Int, event: KeyEvent?, session: TerminalSession?): Boolean =
        false

    override fun onKeyUp(keyCode: Int, event: KeyEvent?): Boolean = false

    override fun onLongPress(e: MotionEvent?): Boolean = false

    override fun readControlKey(): Boolean = false
    override fun readAltKey(): Boolean = false
    override fun readShiftKey(): Boolean = false
    override fun readFnKey(): Boolean = false

    override fun onCodePoint(codePoint: Int, ctrl: Boolean, session: TerminalSession?): Boolean =
        false

    override fun onEmulatorSet() {}

    override fun logError(tag: String, message: String) { Log.e(tag, message) }
    override fun logWarn(tag: String, message: String) { Log.w(tag, message) }
    override fun logInfo(tag: String, message: String) { Log.i(tag, message) }
    override fun logDebug(tag: String, message: String) { Log.d(tag, message) }
    override fun logVerbose(tag: String, message: String) { Log.v(tag, message) }
    override fun logStackTraceWithMessage(tag: String, message: String, e: Exception) {
        Log.e(tag, message, e)
    }

    override fun logStackTrace(tag: String, e: Exception) { Log.e(tag, "exception", e) }
}

