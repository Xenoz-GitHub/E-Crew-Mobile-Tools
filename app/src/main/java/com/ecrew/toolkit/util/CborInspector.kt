package com.ecrew.toolkit.util

/**
 * Minimal, dependency-free CBOR (RFC 8949) decoder that renders a payload as
 * an indented tree with byte offsets. Strict: returns null unless the root item
 * consumes the whole buffer. Supports indefinite-length chunks and all basic
 * types (uint/nint/bytes/text/array/map/tag/simple/float16-32-64).
 */
object CborInspector {

    private const val MAX_DEPTH = 32
    private const val MAX_ITEMS = 20000

    fun decodeToTree(data: ByteArray): String? {
        if (data.isEmpty() || data.size > 256 * 1024) return null
        val st = State(data)
        val out = StringBuilder()
        return try {
            if (!readItem(st, 0, out)) return null
            if (st.p != data.size) return null
            out.toString()
        } catch (e: Exception) {
            null
        }
    }

    private class State(val d: ByteArray) {
        var p = 0
        var items = 0
    }

    private fun u8(st: State): Int {
        if (st.p >= st.d.size) throw IndexOutOfBoundsException()
        return st.d[st.p++].toInt() and 0xFF
    }

    private fun be(st: State, n: Int): Long {
        var v = 0L
        repeat(n) { v = (v shl 8) or (u8(st).toLong() and 0xFF) }
        return v
    }

    /** Returns the value length / immediate value; -1 means indefinite. */
    private fun head(st: State, ai: Int): Long = when {
        ai < 24 -> ai.toLong()
        ai == 24 -> be(st, 1)
        ai == 25 -> be(st, 2)
        ai == 26 -> be(st, 4)
        ai == 27 -> be(st, 8)
        ai == 31 -> -1L
        else -> throw IllegalStateException("reserved additional info $ai")
    }

    private fun readItem(st: State, depth: Int, out: StringBuilder): Boolean {
        if (depth > MAX_DEPTH) return false
        if (++st.items > MAX_ITEMS) return false
        if (st.p >= st.d.size) return false

        val start = st.p
        val ib = u8(st)
        val major = ib shr 5
        val ai = ib and 0x1F
        val indent = "  ".repeat(depth)

        when (major) {
            0 -> { // unsigned int
                val v = head(st, ai)
                out.append("$indent@$start: uint $v\n")
            }
            1 -> { // negative int
                val v = head(st, ai)
                out.append("$indent@$start: negint ${-1 - v}\n")
            }
            2 -> { // byte string
                val v = head(st, ai)
                if (v < 0) { // indefinite length
                    out.append("$indent@$start: bytes (indefinite)\n")
                    while (true) {
                        if (st.p >= st.d.size) return false
                        if ((st.d[st.p].toInt() and 0xFF) == 0xFF) { st.p++; break }
                        if (!readItem(st, depth + 1, out)) return false
                    }
                } else {
                    if (st.p + v > st.d.size) return false
                    val bytes = st.d.copyOfRange(st.p, st.p + v.toInt())
                    st.p += v.toInt()
                    out.append("$indent@$start: bytes(${len(v)}) ${hexPreview(bytes)}\n")
                }
            }
            3 -> { // text string
                val v = head(st, ai)
                if (v < 0) {
                    out.append("$indent@$start: text (indefinite)\n")
                    while (true) {
                        if (st.p >= st.d.size) return false
                        if ((st.d[st.p].toInt() and 0xFF) == 0xFF) { st.p++; break }
                        if (!readItem(st, depth + 1, out)) return false
                    }
                } else {
                    if (st.p + v > st.d.size) return false
                    val bytes = st.d.copyOfRange(st.p, st.p + v.toInt())
                    st.p += v.toInt()
                    out.append("$indent@$start: text(${len(v)}) \"${clip(String(bytes, Charsets.UTF_8))}\"\n")
                }
            }
            4 -> { // array
                val n = head(st, ai)
                if (n < 0) {
                    out.append("$indent@$start: array [\n")
                    while (true) {
                        if (st.p >= st.d.size) return false
                        if ((st.d[st.p].toInt() and 0xFF) == 0xFF) { st.p++; break }
                        if (!readItem(st, depth + 1, out)) return false
                    }
                    out.append("$indent]\n")
                } else {
                    out.append("$indent@$start: array[${len(n)}]\n")
                    repeat(n.toInt()) { if (!readItem(st, depth + 1, out)) return false }
                }
            }
            5 -> { // map
                val n = head(st, ai)
                if (n < 0) {
                    out.append("$indent@$start: map {\n")
                    while (true) {
                        if (st.p >= st.d.size) return false
                        if ((st.d[st.p].toInt() and 0xFF) == 0xFF) { st.p++; break }
                        if (!readItem(st, depth + 1, out)) return false
                        if (!readItem(st, depth + 1, out)) return false
                    }
                    out.append("$indent}\n")
                } else {
                    out.append("$indent@$start: map{${len(n)}}\n")
                    repeat(n.toInt()) {
                        if (!readItem(st, depth + 1, out)) return false
                        if (!readItem(st, depth + 1, out)) return false
                    }
                }
            }
            6 -> { // tag
                val tag = head(st, ai)
                out.append("$indent@$start: tag($tag)\n")
                if (!readItem(st, depth + 1, out)) return false
            }
            7 -> { // simple / float
                when (ai) {
                    20 -> out.append("$indent@$start: false\n")
                    21 -> out.append("$indent@$start: true\n")
                    22 -> out.append("$indent@$start: null\n")
                    23 -> out.append("$indent@$start: undefined\n")
                    25 -> { val bits = be(st, 2).toInt(); out.append("$indent@$start: f16 ${halfToFloat(bits)}\n") }
                    26 -> { val bits = be(st, 4).toInt(); out.append("$indent@$start: f32 ${Float.fromBits(bits)}\n") }
                    27 -> { val bits = be(st, 8); out.append("$indent@$start: f64 ${Double.fromBits(bits)}\n") }
                    in 0..19 -> out.append("$indent@$start: simple($ai)\n")
                    in 24..255 -> { val v = head(st, 24); out.append("$indent@$start: simple($v)\n") }
                    else -> return false
                }
            }
            else -> return false
        }
        return true
    }

    private fun halfToFloat(bits: Int): Float {
        val sign = if ((bits and 0x8000) != 0) -1 else 1
        val exp = (bits shr 10) and 0x1F
        val frac = bits and 0x3FF
        return when (exp) {
            0 -> sign * frac * 5.960464477539063e-7f  // 2^-24 subnormals
            31 -> if (frac == 0) sign * Float.POSITIVE_INFINITY else Float.NaN
            else -> sign * (1 + frac / 1024f) * Math.pow(2.0, (exp - 15).toDouble()).toFloat()
        }
    }

    private fun len(v: Long) = if (v > Int.MAX_VALUE) "huge" else v.toString()

    private fun hexPreview(b: ByteArray): String {
        val n = minOf(b.size, 32)
        val sb = StringBuilder()
        for (i in 0 until n) sb.append("%02X".format(b[i]))
        if (b.size > n) sb.append("...")
        return sb.toString()
    }

    private fun clip(s: String) =
        if (s.length > 120) s.substring(0, 120) + "..." else s
}
