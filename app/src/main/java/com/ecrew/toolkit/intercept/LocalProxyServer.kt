package com.ecrew.toolkit.intercept

import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.util.Collections
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit

class ProxyException(message: String, cause: Throwable? = null) : Exception(message, cause)

data class ProxyEndpoint(val host: String, val port: Int)

/**
 * Loopback-only HTTP CONNECT forwarder. It never terminates TLS and never logs bodies.
 * CONNECT is relayed to the operator's upstream proxy; plain HTTP is forwarded to the
 * upstream or directly to the origin. The only permitted bind address is loopback.
 */
class LocalProxyServer(
    private val port: Int = DEFAULT_PORT,
    private val upstream: ProxyEndpoint? = null,
    private val log: ProxyLog = ProxyLog(),
    private val bindAddress: String = "127.0.0.1"
) : Closeable {
    private var server: ServerSocket? = null
    private val workers = Executors.newFixedThreadPool(8) { runnable ->
        Thread(runnable, "ecrew-proxy-worker").apply { isDaemon = true }
    }
    private val active: MutableSet<Socket> = Collections.synchronizedSet(mutableSetOf())
    @Volatile
    private var accepting = false
    private var acceptThread: Thread? = null

    val boundPort: Int get() = server?.localPort ?: port

    fun start() {
        if (server != null) return
        val address = try {
            InetAddress.getByName(bindAddress)
        } catch (error: Exception) {
            throw ProxyException("invalid bind address", error)
        }
        if (!address.isLoopbackAddress) {
            throw ProxyException("proxy may only bind to a loopback address")
        }
        if (port !in 0..65535) throw ProxyException("invalid port")
        server = try {
            ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(address, port))
            }
        } catch (error: Exception) {
            throw ProxyException("cannot bind proxy port $port", error)
        }
        accepting = true
        acceptThread = Thread({ acceptLoop() }, "ecrew-proxy-accept").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        accepting = false
        try {
            server?.close()
        } catch (_: Exception) {
            // Closing an already closed listener is harmless.
        }
        server = null
        synchronized(active) {
            active.forEach { socket ->
                try {
                    socket.close()
                } catch (_: Exception) {
                    // Best effort shutdown.
                }
            }
            active.clear()
        }
        workers.shutdownNow()
    }

    override fun close() = stop()

    private fun acceptLoop() {
        while (accepting) {
            val client = try {
                server?.accept() ?: break
            } catch (_: Exception) {
                if (!accepting) break else continue
            }
            active.add(client)
            try {
                workers.execute { handle(client) }
            } catch (_: RejectedExecutionException) {
                closeQuietly(client)
            }
        }
    }

    private fun handle(client: Socket) {
        try {
            client.soTimeout = SOCKET_TIMEOUT_MS
            client.tcpNoDelay = true
            val requestHead = readHead(client.getInputStream()) ?: return
            val request = ParsedRequest.parse(requestHead) ?: run {
                sendError(client, 400, "Bad Request")
                return
            }
            if (request.method == "CONNECT") {
                handleConnect(client, request)
            } else {
                handlePlain(client, request)
            }
        } catch (_: Exception) {
            sendError(client, 502, "Bad Gateway")
        } finally {
            active.remove(client)
            closeQuietly(client)
        }
    }

    private fun handleConnect(client: Socket, request: ParsedRequest) {
        val target = parseAuthority(request.target)
        if (target == null) {
            sendError(client, 400, "Bad CONNECT target")
            log.record(
                "CONNECT", request.target, "", 400, 0, 0, request.headers,
                "invalid CONNECT target"
            )
            return
        }
        val endpoint = upstream ?: target
        val remote = try {
            Socket().apply {
                soTimeout = SOCKET_TIMEOUT_MS
                connect(InetSocketAddress(endpoint.host, endpoint.port), CONNECT_TIMEOUT_MS)
            }
        } catch (error: Exception) {
            sendError(client, 502, "Upstream connect failed")
            log.record(
                "CONNECT", target.host, ":" + target.port, 502, 0, 0, request.headers,
                "connect failed: ${error.javaClass.simpleName}"
            )
            return
        }
        try {
            if (upstream != null) {
                val connectHead = "CONNECT ${target.host}:${target.port} HTTP/1.1\r\n" +
                    "Host: ${target.host}:${target.port}\r\n\r\n"
                remote.getOutputStream().write(connectHead.toByteArray(Charsets.ISO_8859_1))
                remote.getOutputStream().flush()
                val upstreamResponse = readHead(remote.getInputStream())
                if (upstreamResponse == null || !upstreamResponse.startsWith("HTTP/1.")) {
                    sendError(client, 502, "Upstream CONNECT failed")
                    log.record(
                        "CONNECT", target.host, ":" + target.port, 502, 0, 0,
                        request.headers, "upstream returned no CONNECT response"
                    )
                    return
                }
                val status = parseStatus(upstreamResponse)
                if (status !in 200..299) {
                    client.getOutputStream().write(
                        upstreamResponse.toByteArray(Charsets.ISO_8859_1)
                    )
                    client.getOutputStream().flush()
                    log.record(
                        "CONNECT", target.host, ":" + target.port, status, 0, 0,
                        request.headers, "upstream refused CONNECT"
                    )
                    return
                }
            }
            val established = "HTTP/1.1 200 Connection Established\r\n\r\n"
            client.getOutputStream().write(established.toByteArray(Charsets.ISO_8859_1))
            client.getOutputStream().flush()
            log.record(
                "CONNECT", target.host, ":" + target.port, 200, 0, 0, request.headers,
                "TLS terminated upstream"
            )
            pumpBidirectional(client, remote)
        } finally {
            closeQuietly(remote)
        }
    }

    private fun handlePlain(client: Socket, request: ParsedRequest) {
        val absolute = try {
            if (request.target.startsWith("http://", ignoreCase = true)) {
                URI(request.target)
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
        val hostHeader = request.header("Host")
        val host = absolute?.host ?: hostHeader?.substringBefore(':') ?: ""
        val port = absolute?.port?.takeIf { it > 0 } ?: hostHeader?.substringAfter(':', "")
            ?.toIntOrNull() ?: 80
        val path = if (absolute != null) {
            absolute.rawPath?.ifBlank { "/" }?.let { base ->
                absolute.rawQuery?.let { "$base?$it" } ?: base
            } ?: request.target
        } else {
            request.target
        }
        if (host.isBlank()) {
            sendError(client, 400, "Missing Host")
            log.record(request.method, "", request.target, 400, 0, 0, request.headers, null)
            return
        }
        val endpoint = upstream ?: ProxyEndpoint(host, port)
        val remote = try {
            Socket().apply {
                soTimeout = SOCKET_TIMEOUT_MS
                connect(InetSocketAddress(endpoint.host, endpoint.port), CONNECT_TIMEOUT_MS)
            }
        } catch (error: Exception) {
            sendError(client, 502, "Origin connect failed")
            log.record(
                request.method, host, path, 502, 0, 0, request.headers,
                "connect failed: ${error.javaClass.simpleName}"
            )
            return
        }
        try {
            val headerLines = request.headers.joinToString("\r\n") { (name, value) ->
                "$name: $value"
            }
            val requestTarget = if (upstream == null) path else request.target
            val head = "${request.method} $requestTarget HTTP/1.1\r\n$headerLines\r\n\r\n"
            val remoteOut = remote.getOutputStream()
            remoteOut.write(head.toByteArray(Charsets.ISO_8859_1))
            val bodyLength = request.contentLength
            var upBytes = head.toByteArray(Charsets.ISO_8859_1).size.toLong()
            upBytes += copyExact(client.getInputStream(), remoteOut, bodyLength)
            remoteOut.flush()
            val responseHead = readHead(remote.getInputStream())
            if (responseHead == null) {
                sendError(client, 502, "Empty origin response")
                log.record(request.method, host, path, 502, upBytes, 0, request.headers, null)
                return
            }
            val status = parseStatus(responseHead)
            val responseHeaders = parseHeaders(responseHead)
            val responseLength = responseHeaders.firstOrNull {
                it.first.equals("Content-Length", ignoreCase = true)
            }?.second?.toLongOrNull() ?: -1L
            val clientOut = client.getOutputStream()
            clientOut.write(responseHead.toByteArray(Charsets.ISO_8859_1))
            clientOut.flush()
            var downBytes = responseHead.toByteArray(Charsets.ISO_8859_1).size.toLong()
            downBytes += if (responseLength >= 0) {
                copyExact(remote.getInputStream(), clientOut, responseLength)
            } else {
                remote.getInputStream().copyTo(clientOut, COPY_BUFFER)
            }
            clientOut.flush()
            log.record(
                request.method, host, path, status, upBytes, downBytes, request.headers,
                "TLS not terminated by E-Crew"
            )
        } finally {
            closeQuietly(remote)
        }
    }

    private fun pumpBidirectional(client: Socket, remote: Socket) {
        val downThread = Thread({
            try {
                remote.getInputStream().copyTo(client.getOutputStream(), COPY_BUFFER)
                client.getOutputStream().flush()
            } catch (_: Exception) {
                // Tunnel closed by either side.
            } finally {
                closeQuietly(client)
                closeQuietly(remote)
            }
        }, "ecrew-proxy-down").apply {
            isDaemon = true
            start()
        }
        try {
            client.getInputStream().copyTo(remote.getOutputStream(), COPY_BUFFER)
            remote.getOutputStream().flush()
        } catch (_: Exception) {
            // Tunnel closed by either side.
        } finally {
            closeQuietly(client)
            closeQuietly(remote)
        }
        downThread.join(2_000)
    }

    private fun sendError(socket: Socket, code: Int, reason: String) {
        try {
            val body = "$code $reason\n"
            socket.getOutputStream().write(
                ("HTTP/1.1 $code $reason\r\nContent-Type: text/plain\r\n" +
                    "Content-Length: ${body.length}\r\nConnection: close\r\n\r\n$body")
                    .toByteArray(Charsets.US_ASCII)
            )
            socket.getOutputStream().flush()
        } catch (_: Exception) {
            // Client already gone.
        }
    }

    private fun readHead(input: InputStream): String? {
        val output = ByteArrayOutputStream()
        var matched = 0
        val delimiter = byteArrayOf(13, 10, 13, 10)
        while (output.size() < MAX_HEAD_BYTES) {
            val next = input.read()
            if (next < 0) return null
            output.write(next)
            if (next.toByte() == delimiter[matched]) {
                matched++
                if (matched == delimiter.size) {
                    return output.toByteArray().toString(Charsets.ISO_8859_1)
                }
            } else {
                matched = if (next.toByte() == delimiter[0]) 1 else 0
            }
        }
        return null
    }

    private fun copyExact(input: InputStream, output: OutputStream, count: Long): Long {
        if (count <= 0) return 0
        var remaining = count
        var total = 0L
        val buffer = ByteArray(COPY_BUFFER)
        while (remaining > 0) {
            val read = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
            if (read < 0) break
            output.write(buffer, 0, read)
            remaining -= read
            total += read
        }
        return total
    }

    private fun parseAuthority(value: String): ProxyEndpoint? {
        val host: String
        val portText: String
        if (value.startsWith("[")) {
            val end = value.indexOf(']')
            if (end < 0 || end + 1 >= value.length || value[end + 1] != ':') return null
            host = value.substring(1, end)
            portText = value.substring(end + 2)
        } else {
            val index = value.lastIndexOf(':')
            if (index <= 0 || index == value.lastIndex) return null
            host = value.substring(0, index)
            portText = value.substring(index + 1)
        }
        val port = portText.toIntOrNull() ?: return null
        if (port !in 1..65535 || host.isBlank() || host.contains('/')) return null
        return ProxyEndpoint(host, port)
    }

    private fun parseStatus(head: String): Int =
        head.lineSequence().firstOrNull()?.split(' ')?.getOrNull(1)?.toIntOrNull() ?: 502

    private fun parseHeaders(head: String): List<Pair<String, String>> =
        head.lineSequence().drop(1).mapNotNull { line ->
            if (line.isBlank() || line[0].isWhitespace()) null else {
                val index = line.indexOf(':')
                if (index <= 0) null else line.substring(0, index) to line.substring(index + 1).trim()
            }
        }.toList()

    private fun closeQuietly(socket: Socket) {
        try {
            socket.close()
        } catch (_: Exception) {
            // Already closed.
        }
    }

    private data class ParsedRequest(
        val method: String,
        val target: String,
        val headers: List<Pair<String, String>>
    ) {
        val contentLength: Long
            get() = headers.firstOrNull {
                it.first.equals("Content-Length", ignoreCase = true)
            }?.second?.toLongOrNull()?.coerceAtLeast(0) ?: 0

        fun header(name: String): String? =
            headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

        companion object {
            fun parse(head: String): ParsedRequest? {
                val lines = head.split("\r\n")
                val first = lines.firstOrNull() ?: return null
                val parts = first.split(' ', limit = 8)
                if (parts.size < 3 || !parts[2].startsWith("HTTP/")) return null
                if (parts[0].isBlank() || parts[1].isBlank()) return null
                val headers = lines.drop(1).takeWhile { it.isNotBlank() }.mapNotNull { line ->
                    val index = line.indexOf(':')
                    if (index <= 0) null else {
                        val name = line.substring(0, index).trim()
                        if (name.any { it <= ' ' }) null else {
                            name to line.substring(index + 1).trim()
                        }
                    }
                }
                return ParsedRequest(parts[0].uppercase(), parts[1], headers)
            }
        }
    }

    companion object {
        const val DEFAULT_PORT = 8877
        private const val MAX_HEAD_BYTES = 64 * 1024
        private const val COPY_BUFFER = 8 * 1024
        private const val SOCKET_TIMEOUT_MS = 30_000
        private const val CONNECT_TIMEOUT_MS = 10_000
    }
}
