package com.ecrew.agent

import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts

/**
 * First-launch consent gate (spec Component 5 / consent flow): full-screen disclosure,
 * operator name (prefilled from an intent extra), a mandatory legal-attestation checkbox,
 * and the accessibility-settings round trip with inline error + Retry.
 *
 * Cancel closes the app. Enabling stores consent in EncryptedSharedPreferences, generates
 * the pairing code, and only proceeds to listening once accessibility access is verified.
 */
class ConsentActivity : ComponentActivity() {

    private var awaitingAccessibilityReturn = false

    private val bluetoothPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
            // Denial is handled visibly elsewhere: LAN still works; the rest of the feature
            // is unaffected.
            accessibilityCheck()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.consent_activity)

        val operatorInput = findViewById<EditText>(R.id.operator_input)
        val consentCheck = findViewById<CheckBox>(R.id.consent_check)
        val adbToggle = findViewById<CheckBox>(R.id.adb_toggle)
        val errorText = findViewById<TextView>(R.id.error_text)

        val prefilled = intent.getStringExtra(EXTRA_OPERATOR_NAME) ?: Prefs.operatorName(this)
        operatorInput.setText(prefilled)
        adbToggle.isChecked = Prefs.adbHardening(this)

        findViewById<Button>(R.id.cancel_button).setOnClickListener {
            finishAffinity()
        }

        findViewById<Button>(R.id.enable_button).setOnClickListener {
            val operator = operatorInput.text.toString().trim()
            if (!consentCheck.isChecked || operator.isEmpty()) {
                errorText.visibility = View.VISIBLE
                errorText.setText(R.string.consent_error_fields)
                return@setOnClickListener
            }
            Prefs.grantConsent(this, operator)
            Prefs.setAdbHardening(this, adbToggle.isChecked)
            Prefs.regeneratePairingCode(this)
            errorText.visibility = View.GONE
            requestBluetoothThenCheck()
        }

        findViewById<Button>(R.id.retry_button).setOnClickListener { accessibilityCheck() }
    }

    override fun onResume() {
        super.onResume()
        if (awaitingAccessibilityReturn && EcrewAccessibilityService.isEnabled(this)) {
            awaitingAccessibilityReturn = false
            proceedToStatus()
        }
    }

    private fun requestBluetoothThenCheck() {
        if (Build.VERSION.SDK_INT >= 31) {
            bluetoothPermissionLauncher.launch(
                arrayOf(Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE)
            )
        } else {
            accessibilityCheck()
        }
    }

    private fun accessibilityCheck() {
        if (EcrewAccessibilityService.isEnabled(this) || EcrewAccessibilityService.instance() != null) {
            proceedToStatus()
            return
        }
        awaitingAccessibilityReturn = true
        findViewById<TextView>(R.id.error_text).apply {
            visibility = View.VISIBLE
            setText(R.string.consent_error_accessibility)
        }
        findViewById<Button>(R.id.retry_button).visibility = View.VISIBLE
        runCatching { startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) }
    }

    private fun proceedToStatus() {
        RemoteAgentService.start(this)
        startActivity(Intent(this, AgentStatusActivity::class.java))
        finish()
    }

    companion object {
        const val EXTRA_OPERATOR_NAME = "operator_name"
    }
}
