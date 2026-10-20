package com.ecrew.toolkit.capture

import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector

/**
 * User-space IPv4 forwarder for the local loopback VPN (PCAPdroid-style):
 *  - tunThread: blocking TUN reads -> PCAP file -> queue
 *  - coreThread: selector loop owning ALL flow state; forwards device traffic
 *    to the real network through protected sockets and synthesises the
 *    return packets back into the TUN.
 * Everything is written to a pcap file (LINKTYPE_RAW) plus a metadata log
 * (DNS names, HTTP URLs, TLS SNI, TCP flows) via CaptureBus.
 * IPv6 is intentionally not routed into the VPN (no v6 rewrite support).
 */
class CaptureEngine(
    private val service: VpnService,
    private val tun: ParcelFileDescriptor,
    private val pcapFile: RandomAccessFile
) {

    @Volatile
    var running = false

    private val queue = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
    private lateinit var selector: Selector
    private var tunThread: Thread? = null
    private var coreThread: Thread? = null
    private val tunWriteLock = Any()
    private var tunOut: FileOutputStream? = null

    class TcpFlow(
        val key: String,
        val clientIp: ByteArray,
        val serverIp: ByteArray,
        val clientPort: Int,
        val serverPort: Int
    ) {
        var channel: java.nio.channels.SocketChannel? = null
        var connected = false
        var ourSeq: Long = System.nanoTime() and 0x7FFFFFFFL
        var clientNextSeq: Long = 0
        var clientFinSeq: Long = -1
        var ourFinSent = false
        val pendingToServer = ArrayDeque<ByteArray>()
        var lastActive = System.currentTimeMillis()
    }

    class UdpFlow(
        val clientIp: ByteArray,
        val serverIp: ByteArray,
        val clientPort: Int,
        val serverPort: Int,
        val channel: java.nio.channels.DatagramChannel
    ) {
        var lastActive = System.currentTimeMillis()
    }

    companion object {
        /** Standard pcap global header: magic A1B2C3D4, v2.4, snaplen 65535,
         *  DLT_RAW (101) - TUN delivers bare IPv4 packets. */
        fun writePcapHeader(raf: RandomAccessFile) {
            raf.setLength(0)
            raf.writeInt(0xA1B2C3D4.toInt())
            raf.writeShort(2)
            raf.writeShort(4)
            raf.writeInt(0)
            raf.writeInt(0)
            raf.writeInt(65535)
            raf.writeInt(101)
        }
    }

    fun start() {
        running = true
        selector = Selector.open()
        tunOut = FileOutputStream(tun.fileDescriptor)
        tunThread = Thread({ tunLoop() }, "cap-tun").apply {
            isDaemon = true
            start()
        }
        coreThread = Thread({ coreLoop() }, "cap-core").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        running = false
        try { selector.wakeup() } catch (e: Exception) {}
        try { tunThread?.join(1500) } catch (e: Exception) {}
        try { coreThread?.join(2000) } catch (e: Exception) {}
        try { selector.close() } catch (e: Exception) {}
        synchronized(tunWriteLock) { try { tunOut?.close() } catch (e: Exception) {} }
        synchronized(pcapFile) {
            try { pcapFile.fd.sync() } catch (e: Exception) {}
        }
    }

    private fun tunLoop() {
        val fis = FileInputStream(tun.fileDescriptor)
        val buf = ByteArray(32767)
        while (running) {
            val n = try { fis.read(buf) } catch (e: Exception) { -1 }
            if (n < 0) break
            if (n == 0) continue
            val pkt = buf.copyOf(n)
            writePcap(pkt)
            CaptureBus.statsPackets++
            CaptureBus.statsBytes += n
            queue.offer(pkt)
            try { selector.wakeup() } catch (e: Exception) {}
        }
    }

    /** Append one raw frame to the pcap (called from both threads -> lock). */
    private fun writePcap(pkt: ByteArray) {
        synchronized(pcapFile) {
            try {
                val now = System.currentTimeMillis()
                pcapFile.writeInt((now / 1000).toInt())
                pcapFile.writeInt(((now % 1000) * 1000).toInt())
                pcapFile.writeInt(pkt.size)
                pcapFile.writeInt(pkt.size)
                pcapFile.write(pkt)
            } catch (e: Exception) {
                // disk full etc: stop trying next time
            }
        }
    }

    /** Write a synthesized packet to the TUN and mirror it into the pcap. */
    private fun toTun(pkt: ByteArray) {
        synchronized(tunWriteLock) {
            try { tunOut?.write(pkt) } catch (e: Exception) {}
        }
        writePcap(pkt)
        CaptureBus.statsPackets++
        CaptureBus.statsBytes += pkt.size
    }

    // ------------------------------------------------------------- core loop

    private fun coreLoop() {
        var lastMaint = 0L
        while (running) {
            var pkt: ByteArray?
            while (queue.poll().also { pkt = it } != null) {
                try { handleTunPacket(pkt!!) } catch (e: Exception) {
                    CaptureBus.add("ERROR", "handle: ${e.message}")
                }
            }
            try {
                if (selector.select(500) > 0) {
                    val it = selector.selectedKeys().iterator()
                    while (it.hasNext()) {
                        val key = it.next()
                        it.remove()
                        try {
                            handleKey(key)
                        } catch (e: Exception) {
                            CaptureBus.add("ERROR", "io: ${e.message}")
                            closeKey(key)
                        }
                    }
                }
            } catch (e: Exception) {
                if (running) CaptureBus.add("ERROR", "selector: ${e.message}")
                break
            }
            val now = System.currentTimeMillis()
            if (now - lastMaint > 5000) {
                lastMaint = now
                maintenance(now)
            }
        }
        cleanup()
    }

    private fun handleTunPacket(raw: ByteArray) {
        val ip = PacketUtil.parseIp(raw) ?: return
        when (ip.proto) {
            6 -> handleTcp(ip)
            17 -> handleUdp(ip)
        }
    }

    // ------------------------------------------------------------------ TCP

    private fun handleTcp(ip: PacketUtil.IpPacket) {
        val seg = PacketUtil.parseTcp(ip) ?: return
        val key = keyOf(seg.ip.src, seg.sport, seg.ip.dst, seg.dport)

        if (seg.rst) {
            tcpFlows.remove(key)?.channel?.let { c -> runCatching { c.close() } }
            return
        }

        if (seg.syn) {
            if (tcpFlows.containsKey(key)) return
            val flow = TcpFlow(key, seg.ip.src, seg.ip.dst, seg.sport, seg.dport)
            tcpFlows[key] = flow
            flow.clientNextSeq = seg.seq + 1
            CaptureBus.add(
                "TCP",
                "${ipStr(seg.ip.src)}:${seg.sport} -> ${ipStr(seg.ip.dst)}:${seg.dport}"
            )
            sendToClient(flow, 0x12, ByteArray(0), flow.ourSeq, flow.clientNextSeq)
            flow.ourSeq += 1
            openUpstream(flow, key)
            return
        }

        val flow = tcpFlows[key]
        if (flow == null) {
            sendRst(seg)
            return
        }
        flow.lastActive = System.currentTimeMillis()

        val payload = seg.payload()
        if (payload.isNotEmpty()) {
            flow.clientNextSeq = seg.seq + payload.size
            inspectClient(flow, payload)
            if (flow.connected) writeToUpstream(flow, payload)
            else if (flow.pendingToServer.size < 64) flow.pendingToServer.add(payload)
        }
        if (seg.fin && flow.clientFinSeq < 0) {
            flow.clientFinSeq = seg.seq + payload.size + 1
            sendToClient(flow, 0x10, ByteArray(0), flow.ourSeq, flow.clientNextSeq)
            try { flow.channel?.shutdownOutput() } catch (e: Exception) {}
        }
    }

    private fun openUpstream(flow: TcpFlow, key: String) {
        try {
            val ch = java.nio.channels.SocketChannel.open()
            service.protect(ch.socket())
            ch.configureBlocking(false)
            ch.connect(java.net.InetSocketAddress(ipStr(flow.serverIp), flow.serverPort))
            flow.channel = ch
            ch.register(selector, SelectionKey.OP_CONNECT, flow)
            selector.wakeup()
        } catch (e: Exception) {
            CaptureBus.add("ERROR", "connect ${ipStr(flow.serverIp)}: ${e.message}")
            sendRstToFlow(flow)
            tcpFlows.remove(key)
        }
    }

    private fun writeToUpstream(flow: TcpFlow, payload: ByteArray) {
        val ch = flow.channel ?: return
        try {
            val buf = ByteBuffer.wrap(payload)
            while (buf.hasRemaining()) {
                if (ch.write(buf) <= 0) {
                    if (flow.pendingToServer.size < 64) {
                        flow.pendingToServer.add(
                            buf.array().copyOfRange(buf.position(), buf.position() + buf.remaining())
                        )
                    }
                    break
                }
            }
        } catch (e: Exception) {
            CaptureBus.add("ERROR", "write: ${e.message}")
            sendRstToFlow(flow)
            closeFlow(flow)
        }
    }

    /** server -> client segment (seq/ack from flow state). */
    private fun sendToClient(
        flow: TcpFlow, flags: Int, payload: ByteArray, seq: Long, ack: Long
    ) {
        val tcp = PacketUtil.buildTcpSegment(
            flow.serverIp, flow.clientIp, flow.serverPort, flow.clientPort,
            seq, ack, flags, payload
        )
        toTun(PacketUtil.buildIpPacket(6, flow.serverIp, flow.clientIp, tcp))
    }

    private fun sendRst(seg: PacketUtil.TcpSegment) {
        val ack = seg.seq + seg.payloadLen + (if (seg.syn) 1 else 0) + (if (seg.fin) 1 else 0)
        val seq = if (seg.ackFlag) seg.ack else 0L
        val tcp = PacketUtil.buildTcpSegment(
            seg.ip.dst, seg.ip.src, seg.dport, seg.sport, seq, ack, 0x14, ByteArray(0)
        )
        toTun(PacketUtil.buildIpPacket(6, seg.ip.dst, seg.ip.src, tcp))
    }

    private fun sendRstToFlow(flow: TcpFlow) {
        val tcp = PacketUtil.buildTcpSegment(
            flow.serverIp, flow.clientIp, flow.serverPort, flow.clientPort,
            flow.ourSeq, flow.clientNextSeq, 0x14, ByteArray(0)
        )
        toTun(PacketUtil.buildIpPacket(6, flow.serverIp, flow.clientIp, tcp))
    }

    // ---------------------------------------------------- flow tables + UDP

    private val tcpFlows = HashMap<String, TcpFlow>()
    private val udpFlows = HashMap<String, UdpFlow>()

    private fun keyOf(src: ByteArray, sport: Int, dst: ByteArray, dport: Int): String =
        "${ipStr(src)}:$sport>${ipStr(dst)}:$dport"

    private fun ipStr(b: ByteArray): String =
        "${b[0].toInt() and 0xFF}.${b[1].toInt() and 0xFF}." +
            "${b[2].toInt() and 0xFF}.${b[3].toInt() and 0xFF}"

    private fun handleUdp(ip: PacketUtil.IpPacket) {
        val d = PacketUtil.parseUdp(ip) ?: return
        val key = keyOf(d.ip.src, d.sport, d.ip.dst, d.dport)
        var flow = udpFlows[key]
        if (flow == null) {
            try {
                val ch = java.nio.channels.DatagramChannel.open()
                ch.configureBlocking(false)
                service.protect(ch.socket())
                ch.connect(java.net.InetSocketAddress(ipStr(d.ip.dst), d.dport))
                flow = UdpFlow(d.ip.src, d.ip.dst, d.sport, d.dport, ch)
                ch.register(selector, SelectionKey.OP_READ, flow)
                udpFlows[key] = flow
            } catch (e: Exception) {
                CaptureBus.add("ERROR", "udp open: ${e.message}")
                return
            }
        }
        flow.lastActive = System.currentTimeMillis()
        val payload = d.ip.raw.copyOfRange(d.payloadOff, d.payloadOff + d.payloadLen)
        if (d.dport == 53 && PayloadExtract.isDnsQuery(payload)) {
            PayloadExtract.dnsQueryName(payload)?.let {
                CaptureBus.add("DNS", "query $it -> ${ipStr(d.ip.dst)}")
            }
        }
        try {
            val buf = ByteBuffer.wrap(payload)
            while (buf.hasRemaining() && flow.channel.write(buf) > 0) { /* spin until sent */ }
        } catch (e: Exception) {
            CaptureBus.add("ERROR", "udp write: ${e.message}")
        }
    }

    // -------------------------------------------------------- selector keys

    private fun handleKey(key: SelectionKey) {
        when (val att = key.attachment()) {
            is TcpFlow -> handleTcpKey(key, att)
            is UdpFlow -> handleUdpKey(att)
        }
    }

    private fun handleTcpKey(key: SelectionKey, flow: TcpFlow) {
        val ch = flow.channel ?: return
        if (key.isConnectable) {
            try {
                if (ch.finishConnect()) {
                    flow.connected = true
                    key.interestOps(SelectionKey.OP_READ)
                    val batch = flow.pendingToServer.toList()
                    flow.pendingToServer.clear()
                    batch.forEach { writeToUpstream(flow, it) }
                }
            } catch (e: Exception) {
                CaptureBus.add("ERROR", "connect ${ipStr(flow.serverIp)}: ${e.message}")
                sendRstToFlow(flow)
                closeFlow(flow)
            }
            return
        }
        if (key.isReadable) {
            val buf = ByteBuffer.allocate(16384)
            val n = try { ch.read(buf) } catch (e: Exception) { -1 }
            if (n < 0) {
                if (!flow.ourFinSent) {
                    flow.ourFinSent = true
                    sendToClient(flow, 0x11, ByteArray(0), flow.ourSeq, flow.clientNextSeq)
                    flow.ourSeq += 1
                }
                closeFlow(flow)
                return
            }
            if (n > 0) {
                flow.lastActive = System.currentTimeMillis()
                val data = buf.array().copyOf(n)
                sendToClient(flow, 0x18, data, flow.ourSeq, flow.clientNextSeq)
                flow.ourSeq += n
            }
        }
        if (key.isWritable && flow.pendingToServer.isNotEmpty()) {
            val batch = flow.pendingToServer.toList()
            flow.pendingToServer.clear()
            batch.forEach { writeToUpstream(flow, it) }
            if (flow.pendingToServer.isEmpty()) key.interestOps(SelectionKey.OP_READ)
        }
    }

    private fun handleUdpKey(flow: UdpFlow) {
        val buf = ByteBuffer.allocate(65535)
        val n = try { flow.channel.read(buf) } catch (e: Exception) { -1 }
        if (n <= 0) return
        flow.lastActive = System.currentTimeMillis()
        val data = buf.array().copyOf(n)
        val udp = PacketUtil.buildUdpDatagram(
            flow.serverIp, flow.clientIp, flow.serverPort, flow.clientPort, data
        )
        toTun(PacketUtil.buildIpPacket(17, flow.serverIp, flow.clientIp, udp))
    }

    // --------------------------------------------------- metadata + cleanup

    /** Log HTTP URLs and TLS SNI seen on client->server payloads. */
    private fun inspectClient(flow: TcpFlow, payload: ByteArray) {
        try {
            if (PayloadExtract.isHttpRequest(payload)) {
                PayloadExtract.httpRequest(payload)?.let { CaptureBus.add("HTTP", it) }
            } else if (PayloadExtract.isTlsClientHello(payload)) {
                PayloadExtract.tlsSni(payload)?.let {
                    CaptureBus.add("TLS", "SNI $it -> ${ipStr(flow.serverIp)}:${flow.serverPort}")
                }
            }
        } catch (e: Exception) {
            // extraction must never break forwarding
        }
    }

    private fun maintenance(now: Long) {
        val t = tcpFlows.entries.iterator()
        while (t.hasNext()) {
            val e = t.next()
            if (now - e.value.lastActive > 180_000) {
                try { e.value.channel?.close() } catch (x: Exception) {}
                t.remove()
            }
        }
        val u = udpFlows.entries.iterator()
        while (u.hasNext()) {
            val e = u.next()
            if (now - e.value.lastActive > 60_000) {
                try { e.value.channel.close() } catch (x: Exception) {}
                u.remove()
            }
        }
    }

    private fun closeKey(key: SelectionKey) {
        val att = key.attachment()
        try { key.channel().close() } catch (e: Exception) {}
        when (att) {
            is TcpFlow -> tcpFlows.remove(att.key)
            is UdpFlow -> udpFlows.entries.removeIf { it.value === att }
        }
    }

    private fun closeFlow(flow: TcpFlow) {
        try { flow.channel?.close() } catch (e: Exception) {}
        tcpFlows.remove(flow.key)
    }

    private fun cleanup() {
        tcpFlows.values.forEach { try { it.channel?.close() } catch (e: Exception) {} }
        tcpFlows.clear()
        udpFlows.values.forEach { try { it.channel.close() } catch (e: Exception) {} }
        udpFlows.clear()
    }
}

