package com.ecrew.toolkit.capture

/**
 * Minimal IPv4/TCP/UDP packer/parser + checksums for the user-space forwarder
 * and the PCAP writer. Raw TUN frames: LINKTYPE_RAW (IPv4 only - the VPN only
 * routes 0.0.0.0/0, so IPv6 bypasses us untouched).
 */
object PacketUtil {

    private var ipId = (System.nanoTime() and 0xFFFFL).toInt()

    fun u16(b: ByteArray, i: Int): Int =
        ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)

    fun u32(b: ByteArray, i: Int): Long =
        ((b[i].toInt() and 0xFF).toLong() shl 24) or
            ((b[i + 1].toInt() and 0xFF).toLong() shl 16) or
            ((b[i + 2].toInt() and 0xFF).toLong() shl 8) or
            (b[i + 3].toInt() and 0xFF).toLong()

    fun put16(b: ByteArray, i: Int, v: Int) {
        b[i] = ((v shr 8) and 0xFF).toByte()
        b[i + 1] = (v and 0xFF).toByte()
    }

    fun put32(b: ByteArray, i: Int, v: Long) {
        b[i] = ((v shr 24) and 0xFF).toByte()
        b[i + 1] = ((v shr 16) and 0xFF).toByte()
        b[i + 2] = ((v shr 8) and 0xFF).toByte()
        b[i + 3] = (v and 0xFF).toByte()
    }

    /** Internet checksum (RFC 1071) over [off, off+len). */
    fun checksum(data: ByteArray, off: Int, len: Int): Int {
        var sum = 0
        var i = off
        val end = off + len
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (data[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }

    /** Pseudo-header checksum for TCP/UDP over IPv4. */
    private fun transportChecksum(
        src: ByteArray, dst: ByteArray, proto: Int, segment: ByteArray
    ): Int {
        val pseudo = ByteArray(12 + segment.size)
        System.arraycopy(src, 0, pseudo, 0, 4)
        System.arraycopy(dst, 0, pseudo, 4, 4)
        pseudo[9] = proto.toByte()
        put16(pseudo, 10, segment.size)
        System.arraycopy(segment, 0, pseudo, 12, segment.size)
        return checksum(pseudo, 0, pseudo.size)
    }

    /** Wrap a transport payload (TCP/UDP header+data) in an IPv4 packet. */
    fun buildIpPacket(proto: Int, src: ByteArray, dst: ByteArray, body: ByteArray): ByteArray {
        val pkt = ByteArray(20 + body.size)
        pkt[0] = 0x45
        put16(pkt, 2, pkt.size)
        put16(pkt, 4, ipId and 0xFFFF)
        ipId = (ipId + 1) and 0xFFFF
        pkt[8] = 64
        pkt[9] = proto.toByte()
        System.arraycopy(src, 0, pkt, 12, 4)
        System.arraycopy(dst, 0, pkt, 16, 4)
        put16(pkt, 10, checksum(pkt, 0, 20))
        body.copyInto(pkt, 20)
        return pkt
    }

    fun buildTcpSegment(
        src: ByteArray, dst: ByteArray,
        sport: Int, dport: Int,
        seq: Long, ack: Long,
        flags: Int, payload: ByteArray
    ): ByteArray {
        val tcp = ByteArray(20 + payload.size)
        put16(tcp, 0, sport)
        put16(tcp, 2, dport)
        put32(tcp, 4, seq)
        put32(tcp, 8, ack)
        tcp[12] = (5 shl 4).toByte()
        tcp[13] = flags.toByte()
        put16(tcp, 14, 65535)
        payload.copyInto(tcp, 20)
        put16(tcp, 16, transportChecksum(src, dst, 6, tcp))
        return tcp
    }

    fun buildUdpDatagram(
        src: ByteArray, dst: ByteArray, sport: Int, dport: Int, payload: ByteArray
    ): ByteArray {
        val udp = ByteArray(8 + payload.size)
        put16(udp, 0, sport)
        put16(udp, 2, dport)
        put16(udp, 4, udp.size)
        payload.copyInto(udp, 8)
        var c = transportChecksum(src, dst, 17, udp)
        if (c == 0) c = 0xFFFF
        put16(udp, 6, c)
        return udp
    }

    // ------------------------------------------------------------- parsing

    data class IpPacket(
        val raw: ByteArray,
        val src: ByteArray,
        val dst: ByteArray,
        val proto: Int,
        val ipHeaderLen: Int
    )

    fun parseIp(raw: ByteArray): IpPacket? {
        if (raw.size < 20) return null
        if (((raw[0].toInt() shr 4) and 0xF) != 4) return null
        val ihl = (raw[0].toInt() and 0xF) * 4
        if (ihl < 20 || raw.size < ihl) return null
        val total = u16(raw, 2)
        if (total < ihl || total > raw.size) return null
        return IpPacket(raw, raw.copyOfRange(12, 16), raw.copyOfRange(16, 20),
            raw[9].toInt() and 0xFF, ihl)
    }

    data class TcpSegment(
        val ip: IpPacket,
        val sport: Int, val dport: Int,
        val seq: Long, val ack: Long,
        val flags: Int,
        val payloadOff: Int, val payloadLen: Int
    ) {
        val syn get() = flags and 0x02 != 0
        val ackFlag get() = flags and 0x10 != 0
        val fin get() = flags and 0x01 != 0
        val rst get() = flags and 0x04 != 0

        fun payload(): ByteArray =
            if (payloadLen <= 0) EMPTY
            else ip.raw.copyOfRange(payloadOff, payloadOff + payloadLen)

        companion object { private val EMPTY = ByteArray(0) }
    }

    fun parseTcp(ip: IpPacket): TcpSegment? {
        val o = ip.ipHeaderLen
        if (ip.proto != 6 || ip.raw.size < o + 20) return null
        val dataOff = ((ip.raw[o + 12].toInt() shr 4) and 0xF) * 4
        if (dataOff < 20 || ip.raw.size < o + dataOff) return null
        return TcpSegment(
            ip = ip,
            sport = u16(ip.raw, o),
            dport = u16(ip.raw, o + 2),
            seq = u32(ip.raw, o + 4),
            ack = u32(ip.raw, o + 8),
            flags = ip.raw[o + 13].toInt() and 0xFF,
            payloadOff = o + dataOff,
            payloadLen = ip.raw.size - (o + dataOff)
        )
    }

    data class UdpDatagram(
        val ip: IpPacket,
        val sport: Int, val dport: Int,
        val payloadOff: Int, val payloadLen: Int
    )

    fun parseUdp(ip: IpPacket): UdpDatagram? {
        val o = ip.ipHeaderLen
        if (ip.proto != 17 || ip.raw.size < o + 8) return null
        val len = u16(ip.raw, o + 4)
        if (len < 8 || o + len > ip.raw.size) return null
        return UdpDatagram(ip, u16(ip.raw, o), u16(ip.raw, o + 2), o + 8, len - 8)
    }
}
