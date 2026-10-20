package com.ecrew.agent

import java.util.concurrent.CopyOnWriteArrayList

/**
 * In-process state shared between the foreground service and the status activity.
 * Listeners are invoked from arbitrary threads; UI listeners must post to the main thread.
 */
object AgentRuntime {
    @Volatile
    var listening: Boolean = false

    @Volatile
    var operatorName: String = ""

    @Volatile
    var sessionActive: Boolean = false

    @Volatile
    var screenStreaming: Boolean = false

    @Volatile
    var lanEndpoint: String? = null

    @Volatile
    var bluetoothListening: Boolean = false

    @Volatile
    var lastNotice: String? = null

    private val listeners = CopyOnWriteArrayList<() -> Unit>()

    fun addListener(listener: () -> Unit) {
        listeners.add(listener)
    }

    fun removeListener(listener: () -> Unit) {
        listeners.remove(listener)
    }

    fun notifyChanged() {
        for (listener in listeners) {
            runCatching { listener() }
        }
    }
}
