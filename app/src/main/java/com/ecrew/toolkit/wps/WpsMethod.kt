package com.ecrew.toolkit.wps

/** The two WPS enrollee flows supported by the legacy Android client API. */
sealed interface WpsMethod {
    /** Keypad flow: the router's 8-digit WPS PIN. */
    data class Pin(val pin: String) : WpsMethod

    /** Push-button flow: no PIN, the operator presses the router's WPS button. */
    object PushButton : WpsMethod
}
