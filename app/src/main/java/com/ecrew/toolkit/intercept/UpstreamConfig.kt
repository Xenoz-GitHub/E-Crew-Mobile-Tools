package com.ecrew.toolkit.intercept

import com.ecrew.toolkit.audit.AuditStore

/** Validated operator upstream, for example Burp at 192.168.1.20:8080. */
data class UpstreamConfig(val host: String, val port: Int) {
    val endpoint: ProxyEndpoint get() = ProxyEndpoint(host, port)
    val display: String get() = "$host:$port"

    companion object {
        fun parse(value: String): UpstreamConfig {
            val trimmed = value.trim()
            if (trimmed.contains("://")) throw ProxyException("enter host:port without a scheme")
            if (trimmed.count { it == ':' } != 1) throw ProxyException("enter exactly host:port")
            val host = trimmed.substringBefore(':').trim()
            val portText = trimmed.substringAfter(':').trim()
            if (host.isBlank() || host.length > 253) throw ProxyException("invalid host")
            if (host.any { it.isWhitespace() || it == '/' || it == '\\' || it == '@' }) {
                throw ProxyException("invalid host")
            }
            if (host == "127.0.0.1" || host.equals("localhost", ignoreCase = true) ||
                host == "::1"
            ) {
                throw ProxyException("upstream must not be the phone itself")
            }
            val port = portText.toIntOrNull() ?: throw ProxyException("invalid port")
            if (port !in 1..65535) throw ProxyException("port must be 1-65535")
            return UpstreamConfig(host, port)
        }

        fun load(store: AuditStore): UpstreamConfig? {
            val value = store.getSetting(SETTING_UPSTREAM) ?: return null
            return try {
                parse(value)
            } catch (_: ProxyException) {
                null
            }
        }

        fun save(store: AuditStore, config: UpstreamConfig) {
            store.setSetting(SETTING_UPSTREAM, config.display)
        }

        const val SETTING_UPSTREAM = "intercept_upstream"
    }
}
