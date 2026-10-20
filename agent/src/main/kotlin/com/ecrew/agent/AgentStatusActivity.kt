package com.ecrew.agent

import android.content.Context
import android.content.Intent
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts

/**
 * Status screen: device model, the live pairing code, listening endpoints, session state,
 * and the mandatory actions (start/stop listening, new code, end session).
 *
 * Also the activity that presents the SYSTEM screen-capture consent dialog when the agent
 * is asked to stream (ACTION_REQUEST_CAPTURE); the result is routed back to the service.
 */
class AgentStatusActivity : ComponentActivity() {

    private val captureLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            RemoteAgentService.deliverCaptureResult(this, result.resultCode, result.data)
        }

    private val listener: () -> Unit = { runOnUiThread { refreshUi() } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.status_activity)

        findViewById<Button>(R.id.start_button).setOnClickListener {
            RemoteAgentService.start(this)
            refreshUi()
        }
        findViewById<Button>(R.id.stop_button).setOnClickListener {
            RemoteAgentService.stop(this)
            refreshUi()
        }
        findViewById<Button>(R.id.new_code_button).setOnClickListener {
            if (AgentRuntime.listening) {
                RemoteAgentService.newCode(this)
            } else {
                Prefs.regeneratePairingCode(this)
            }
            refreshUi()
        }
        findViewById<Button>(R.id.access_button).setOnClickListener {
            runCatching { startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) }
        }
        findViewById<Button>(R.id.end_session_button).setOnClickListener {
            RemoteAgentService.endSession(this)
        }

        if (intent?.action == ACTION_REQUEST_CAPTURE) {
            requestCapture()
        }
        refreshUi()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.action == ACTION_REQUEST_CAPTURE) {
            requestCapture()
        }
    }

    override fun onStart() {
        super.onStart()
        AgentRuntime.addListener(listener)
        refreshUi()
    }

    override fun onStop() {
        AgentRuntime.removeListener(listener)
        super.onStop()
    }

    private fun requestCapture() {
        val manager = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        captureLauncher.launch(manager.createScreenCaptureIntent())
    }

    private fun refreshUi() {
        val code = Prefs.pairingCode(this).ifEmpty { "------" }
        findViewById<TextView>(R.id.status_model).text =
            getString(R.string.status_model_label, Build.MODEL)
        findViewById<TextView>(R.id.status_code).text = code

        val endpoints = buildList {
            AgentRuntime.lanEndpoint?.let { add("LAN $it") }
            if (AgentRuntime.bluetoothListening) add("Bluetooth RFCOMM")
        }
        findViewById<TextView>(R.id.status_listening).text =
            if (endpoints.isEmpty()) "-" else endpoints.joinToString(" | ")

        val state = findViewById<TextView>(R.id.status_state)
        if (AgentRuntime.sessionActive) {
            state.text = if (AgentRuntime.screenStreaming) {
                getString(R.string.status_state_capturing, AgentRuntime.operatorName)
            } else {
                getString(R.string.status_state_active, AgentRuntime.operatorName)
            }
        } else if (AgentRuntime.listening) {
            state.text = getString(R.string.status_state_waiting)
        } else {
            state.text = getString(R.string.status_state_idle)
        }

        val notice = findViewById<TextView>(R.id.status_notice)
        val noticeText = AgentRuntime.lastNotice
        if (noticeText.isNullOrEmpty()) {
            notice.visibility = View.GONE
        } else {
            notice.visibility = View.VISIBLE
            notice.text = noticeText
        }

        findViewById<Button>(R.id.start_button).visibility =
            if (AgentRuntime.listening) View.GONE else View.VISIBLE
        findViewById<Button>(R.id.stop_button).visibility =
            if (AgentRuntime.listening) View.VISIBLE else View.GONE
        findViewById<Button>(R.id.end_session_button).visibility =
            if (AgentRuntime.sessionActive) View.VISIBLE else View.GONE
    }

    companion object {
        const val ACTION_REQUEST_CAPTURE = "com.ecrew.agent.action.REQUEST_CAPTURE"
    }
}
