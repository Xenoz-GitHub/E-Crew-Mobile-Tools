package com.ecrew.toolkit.capture

/**
 * Offline metadata extraction from captured payloads:
 *  - DNS query names
 *  - HTTP request line + Host header (=> full URL)
 *  - TLS ClientHello SNI
 * All parsing is bounds-checked and best-effort: malformed input -> null.
 */
object PayloadExtract {

    // ---------------------------------------------------------------- DNS

    /** First question name of a DNS message ("example.com"), any type. */
    fun dnsQueryName(msg: ByteArray): String? {
        if (msg.size < 12) return null
        val qd = ((msg[4].toInt() and 0xFF) shl 8) or (msg[5].toInt() and 0xFF)
        if (qd < 1) return null
        val sb = StringBuilder()
        var i = 12
        while (i < msg.size) {
            val len = msg[i].toInt() and 0xFF
            if (len == 0) break
            if (len > 63 || i + len >= msg.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (j in 1..len) sb.append((msg[i + j].toInt() and 0xFF).toChar())
            i += len + 1
        }
        return if (sb.isEmpty()) null else sb.toString()
    }

    fun isDnsQuery(msg: ByteArray): Boolean {
        if (msg.size < 12) return false
        val qr = (msg[2].toInt() shr 7) and 1
        return qr == 0
    }

    // ---------------------------------------------------------------- TLS

    fun isTlsClientHello(p: ByteArray): Boolean {
        if (p.size < 6) return false
        // TLS record: type=22 handshake, version 0x03 0x00..0x04
        return (p[0].toInt() and 0xFF) == 0x16 &&
            (p[1].toInt() and 0xFF) == 0x03 &&
            (p[5].toInt() and 0xFF) == 0x01 // ClientHello
    }

    /** SNI hostname from a TLS ClientHello (first flight, unfragmented). */
    fun tlsSni(p: ByteArray): String? {
        if (!isTlsClientHello(p)) return null
        try {
            var i = 5 + 4                    // record hdr + hs hdr
            i += 2 + 32                       // version + random
            if (i >= p.size) return null
            val sidLen = p[i].toInt() and 0xFF; i += 1 + sidLen
            if (i + 2 > p.size) return null
            val csLen = ((p[i].toInt() and 0xFF) shl 8) or (p[i + 1].toInt() and 0xFF)
            i += 2 + csLen
            if (i >= p.size) return null
            val compLen = p[i].toInt() and 0xFF; i += 1 + compLen
            if (i + 2 > p.size) return null
            val extLen = ((p[i].toInt() and 0xFF) shl 8) or (p[i + 1].toInt() and 0xFF)
            i += 2
            val extEnd = i + extLen
            while (i + 4 <= extEnd && i + 4 <= p.size) {
                val type = ((p[i].toInt() and 0xFF) shl 8) or (p[i + 1].toInt() and 0xFF)
                val len = ((p[i + 2].toInt() and 0xFF) shl 8) or (p[i + 3].toInt() and 0xFF)
                i += 4
                if (i + len > p.size) return null
                if (type == 0) { // server_name
                    var j = i + 2            // list length
                    if (j + 3 > i + len) return null
                    val nameType = p[j].toInt() and 0xFF
                    j += 1
                    val nameLen = ((p[j].toInt() and 0xFF) shl 8) or (p[j + 1].toInt() and 0xFF)
                    j += 2
                    if (nameType == 0 && j + nameLen <= p.size) {
                        return String(p, j, nameLen, Charsets.US_ASCII)
                    }
                }
                i += len
            }
        } catch (e: Exception) {
            return null
        }
        return null
    }

    // --------------------------------------------------------------- HTTP

    private val METHODS = listOf("GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ")

    fun isHttpRequest(p: ByteArray): Boolean {
        if (p.size < 5) return false
        val head = String(p, 0, minOf(p.size, 16), Charsets.US_ASCII)
        return METHODS.any { head.startsWith(it) }
    }

    /** "GET /path?q=1 HTTP/1.1 host=example.com" from a request head. */
    fun httpRequest(p: ByteArray): String? {
        if (!isHttpRequest(p)) return null
        val head = String(p, 0, minOf(p.size, 2048), Charsets.ISO_8859_1)
        val lineEnd = head.indexOf("\r\n").let { if (it < 0) head.length else it }
        val requestLine = head.substring(0, lineEnd).trim()
        val path = requestLine.split(' ').getOrElse(1) { "?" }
        val host = Regex("(?im)^Host:\\s*([^\\r\\n]+)").find(head)?.groupValues?.get(1)?.trim()
            ?: "(no host header)"
        val scheme = if (host.endsWith(":80")) "http" else "http"
        return if (path.startsWith("http")) path else "$scheme://$host$path"
    }
}

