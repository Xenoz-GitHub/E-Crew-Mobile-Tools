package com.ecrew.toolkit.util

import android.content.Context
import java.util.regex.Pattern

/** One rule hit produced by the offline YARA-lite engine. */
data class YaraMatch(
    val rule: String,
    val severity: String,
    val description: String,
    val stringId: String,
    val matchedValue: String,
    val offset: Long
)

/** A compiled string definition. Pattern searches run over an ISO-8859-1
 *  view of the raw bytes so that byte offsets == char offsets. */
internal class YString(
    val id: String,
    val pattern: Pattern,
    val display: String,
    val fullword: Boolean
)

internal sealed class YCond {
    data class StrRef(val id: String) : YCond()            // $a  -> bool
    data class CountRef(val id: String) : YCond()          // #a  -> int
    data class OffsetRef(val id: String) : YCond()         // @a  -> int
    object FileSize : YCond()
    data class IntLit(val v: Long) : YCond()
    data class BoolLit(val v: Boolean) : YCond()
    data class Cmp(val left: YCond, val op: String, val right: YCond) : YCond()
    data class And(val l: List<YCond>) : YCond()
    data class Or(val l: List<YCond>) : YCond()
    data class Not(val c: YCond) : YCond()
    data class Quantified(val quant: String, val ids: List<String>) : YCond()
}

internal class YaraRule(
    val name: String,
    val tags: List<String>,
    val meta: Map<String, String>,
    val strings: List<YString>,
    val condition: YCond
)

/**
 * YARA-lite: parses a practical subset of YARA rules and scans payloads.
 * Supported: rule/meta/strings/condition, text / hex { AA ?? BB } (incl.
 * nibble wildcards) / /regex/ literals, modifiers nocase|wide|ascii|fullword,
 * condition operators and/or/not, $id, #id, @id, filesize, integer compares,
 * "any|all|N of them" and "any|all|N of ($a*, $b)". Not supported: xor,
 * base64 modifiers, jumps [1-4], loops ("for ... in ..."), include.
 * Parse failures are collected per-rule instead of aborting the whole set.
 */
object YaraEngine {

    @Volatile private var rules: List<YaraRule> = emptyList()
    @Volatile private var parseErrors: List<String> = emptyList()

    fun init(context: Context) {
        if (rules.isNotEmpty() || parseErrors.isNotEmpty()) return
        synchronized(this) {
            if (rules.isNotEmpty() || parseErrors.isNotEmpty()) return
            val parsed = mutableListOf<YaraRule>()
            val errors = mutableListOf<String>()
            try {
                val files = context.assets.list("rules") ?: emptyArray()
                for (f in files.filter { it.endsWith(".yar") || it.endsWith(".yara") }) {
                    val text = context.assets.open("rules/$f").bufferedReader().use { it.readText() }
                    YaraParser.parseAll(text, f, parsed, errors)
                }
            } catch (e: Exception) {
                errors.add("assets/rules: ${e.message}")
            }
            rules = parsed
            parseErrors = errors
        }
    }

    fun ruleCount(): Int = rules.size
    fun errors(): List<String> = parseErrors

    /** Scan a text payload against every bundled rule. */
    fun scanAssets(text: String): List<YaraMatch> =
        if (rules.isEmpty()) emptyList() else scan(text.toByteArray(Charsets.UTF_8), "payload")

    /** Scan raw bytes (used by the APK analysis module too). */
    @Suppress("UNUSED_PARAMETER") // `label` kept for caller-side provenance; matches carry rule data
    fun scan(data: ByteArray, label: String): List<YaraMatch> {
        val out = mutableListOf<YaraMatch>()
        if (rules.isEmpty()) return out
        val haystack = String(data, Charsets.ISO_8859_1)
        for (rule in rules) {
            val matches = LinkedHashMap<String, MutableList<Long>>()
            val values = LinkedHashMap<String, String>()
            for (s in rule.strings) {
                val offs = mutableListOf<Long>()
                val m = s.pattern.matcher(haystack)
                while (m.find()) {
                    val at = m.start().toLong()
                    if (s.fullword && !isFullWord(data, at.toInt(), m.end() - m.start())) continue
                    offs.add(at)
                    if (values[s.id].isEmptyOrNull()) values[s.id] = clip(m.group())
                    if (offs.size >= 1000) break
                }
                if (offs.isNotEmpty()) matches[s.id] = offs
            }
            val ctx = Ctx(data, matches, values)
            if (YCondEval.isTrue(rule.condition, ctx)) {
                val firstId = matches.keys.firstOrNull() ?: "<condition>"
                out.add(
                    YaraMatch(
                        rule = rule.name,
                        severity = rule.meta["severity"] ?: "info",
                        description = rule.meta["description"] ?: rule.name,
                        stringId = firstId,
                        matchedValue = values[firstId] ?: "",
                        offset = matches[firstId]?.first() ?: -1L
                    )
                )
            }
        }
        return out
    }

    private class Ctx(
        val data: ByteArray,
        val matches: Map<String, List<Long>>,
        val values: Map<String, String>
    )

    private fun String?.isEmptyOrNull(): Boolean = this == null || isEmpty()

    private fun clip(s: String) = if (s.length > 80) s.take(80) + "..." else s

    private fun isFullWord(data: ByteArray, at: Int, len: Int): Boolean {
        fun alnum(b: Byte): Boolean {
            val c = b.toInt().toChar()
            return c.isLetterOrDigit() || c == '_'
        }
        val before = if (at > 0) data[at - 1] else 0
        val after = if (at + len < data.size) data[at + len] else 0
        return !alnum(before) && !alnum(after)
    }

    // ---------------------------------------------------------- parsing

    private enum class K { ID, NUM, STR, HEX, RX, SYM, EOF }

    private class Tok(val k: K, val text: String, val flags: String = "")

    private class YaraLexer(val src: String) {
        var i = 0
        private var peeked: Tok? = null

        fun next(): Tok {
            peeked?.let { peeked = null; return it }
            return rawNext()
        }

        fun peek(): Tok {
            if (peeked == null) peeked = rawNext()
            return peeked!!
        }

        private fun atEnd() = i >= src.length

        private fun skipWs() {
            while (!atEnd()) {
                val c = src[i]
                when {
                    c.isWhitespace() -> i++
                    c == '/' && i + 1 < src.length && src[i + 1] == '/' -> {
                        while (!atEnd() && src[i] != '\n') i++
                    }
                    c == '/' && i + 1 < src.length && src[i + 1] == '*' -> {
                        i += 2
                        while (i + 1 < src.length && !(src[i] == '*' && src[i + 1] == '/')) i++
                        i = minOf(src.length, i + 2)
                    }
                    else -> return
                }
            }
        }

        /** Token in string-value position: "..." | { hex } | /regex/ */
        fun nextValue(): Tok {
            skipWs()
            if (atEnd()) return Tok(K.EOF, "")
            return when (src[i]) {
                '"' -> readStr()
                '{' -> {
                    i++
                    val end = src.indexOf('}', i)
                    if (end < 0) throw IllegalStateException("unterminated hex pattern at $i")
                    val inner = src.substring(i, end).trim()
                    i = end + 1
                    Tok(K.HEX, inner)
                }
                '/' -> readRegex()
                else -> rawNext()
            }
        }

        /** Best-effort recovery: jump to the next top-level `rule` keyword. */
        fun recoverToNextRule() {
            peeked = null
            val m = Regex("\\brule\\b").find(src, i) ?: run { i = src.length; return }
            i = m.range.first
        }

        private fun rawNext(): Tok {
            skipWs()
            if (atEnd()) return Tok(K.EOF, "")
            val c = src[i]
            return when {
                c == '"' -> readStr()
                c == '/' -> readRegex()
                c == '$' || c == '@' || c == '#' -> {
                    i++
                    val s = i
                    while (!atEnd() && (src[i].isLetterOrDigit() || src[i] == '_')) i++
                    Tok(K.ID, c + src.substring(s, i))
                }
                c.isLetter() || c == '_' -> {
                    val s = i
                    while (!atEnd() && (src[i].isLetterOrDigit() || src[i] == '_' || src[i] == '.')) i++
                    Tok(K.ID, src.substring(s, i))
                }
                c.isDigit() -> {
                    val s = i
                    if (c == '0' && i + 1 < src.length && (src[i + 1] == 'x' || src[i + 1] == 'X')) {
                        i += 2
                        while (!atEnd() && src[i].isHexDigit()) i++
                    } else {
                        while (!atEnd() && src[i].isDigit()) i++
                    }
                    Tok(K.NUM, src.substring(s, i))
                }
                c == '=' || c == '!' || c == '<' || c == '>' -> {
                    i++
                    if (!atEnd() && src[i] == '=') { i++; Tok(K.SYM, "${c}=") } else Tok(K.SYM, c.toString())
                }
                c == '{' || c == '}' || c == '(' || c == ')' || c == ',' || c == ':' ||
                    c == '*' || c == '+' || c == '-' || c == '?' -> {
                    i++; Tok(K.SYM, c.toString())
                }
                else -> throw IllegalStateException("unexpected char '$c' at offset $i")
            }
        }

        private fun readStr(): Tok {
            i++
            val sb = StringBuilder()
            while (!atEnd() && src[i] != '"') {
                if (src[i] == '\\') {
                    i++
                    if (atEnd()) break
                    when (val e = src[i]) {
                        'x' -> {
                            if (i + 2 < src.length) {
                                val hex = src.substring(i + 1, i + 3)
                                sb.append(Integer.parseInt(hex, 16).toChar())
                                i += 2
                            }
                        }
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        '0' -> sb.append('\u0000')
                        else -> sb.append(e)
                    }
                    i++
                } else {
                    sb.append(src[i])
                    i++
                }
            }
            if (atEnd()) throw IllegalStateException("unterminated string literal")
            i++
            return Tok(K.STR, sb.toString())
        }

        private fun readRegex(): Tok {
            i++
            val sb = StringBuilder()
            while (!atEnd() && src[i] != '/') {
                if (src[i] == '\\' && i + 1 < src.length) { sb.append(src[i]); i++ }
                sb.append(src[i]); i++
            }
            if (atEnd()) throw IllegalStateException("unterminated regex literal")
            i++
            val flags = StringBuilder()
            while (!atEnd() && src[i].isLetter()) { flags.append(src[i]); i++ }
            return Tok(K.RX, sb.toString(), flags.toString())
        }
    }

    private fun Char.isHexDigit() = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    // ---------------------------------------------- rule parser

    private object YaraParser {
        private val SECTIONS = setOf("meta", "strings", "condition")
        private val MODIFIERS = setOf("nocase", "wide", "ascii", "fullword")

        fun parseAll(
            src: String,
            origin: String,
            out: MutableList<YaraRule>,
            errors: MutableList<String>
        ) {
            val lex = YaraLexer(src)
            var guard = 0
            while (guard++ < 100_000) {
                val t = lex.next()
                if (t.k == K.EOF) break
                if (t.k == K.ID && t.text == "rule") {
                    try {
                        out.add(parseRule(lex))
                    } catch (e: Exception) {
                        errors.add("$origin: ${e.message}")
                        lex.recoverToNextRule()
                    }
                } else if (t.k == K.ID && t.text == "import") {
                    lex.next() // module name (string) - ignored
                } else {
                    errors.add("$origin: unexpected token '${t.text}'")
                    break
                }
            }
        }

        private fun parseRule(lex: YaraLexer): YaraRule {
            val nameTok = lex.next()
            if (nameTok.k != K.ID || nameTok.text in SECTIONS)
                throw IllegalStateException("expected rule name, got '${nameTok.text}'")
            val tags = mutableListOf<String>()
            if (lex.peek().k == K.SYM && lex.peek().text == ":") {
                lex.next()
                while (true) {
                    val t = lex.next()
                    if (t.k == K.ID) tags.add(t.text)
                    if (lex.peek().k == K.SYM && lex.peek().text == ",") lex.next() else break
                }
            }
            expectSym(lex, "{")

            val meta = LinkedHashMap<String, String>()
            val strings = mutableListOf<YString>()
            var condition: YCond? = null
            while (true) {
                val t = lex.peek()
                when {
                    t.k == K.SYM && t.text == "}" -> { lex.next(); break }
                    t.k == K.ID && t.text == "meta" -> { lex.next(); expectSym(lex, ":"); parseMeta(lex, meta) }
                    t.k == K.ID && t.text == "strings" -> { lex.next(); expectSym(lex, ":"); parseStrings(lex, strings) }
                    t.k == K.ID && t.text == "condition" -> {
                        lex.next(); expectSym(lex, ":")
                        condition = parseOr(lex, strings)
                    }
                    else -> throw IllegalStateException("unexpected '${t.text}' in rule ${nameTok.text}")
                }
            }
            return YaraRule(
                name = nameTok.text,
                tags = tags,
                meta = meta,
                strings = strings,
                condition = condition
                    ?: throw IllegalStateException("rule ${nameTok.text} has no condition")
            )
        }

        private fun sectionAhead(lex: YaraLexer): Boolean {
            val t = lex.peek()
            return (t.k == K.ID && t.text in SECTIONS) || (t.k == K.SYM && t.text == "}")
        }

        private fun parseMeta(lex: YaraLexer, meta: MutableMap<String, String>) {
            while (!sectionAhead(lex)) {
                val key = lex.next()
                if (key.k != K.ID) throw IllegalStateException("bad meta key '${key.text}'")
                expectSym(lex, "=")
                val v = lex.next()
                when (v.k) {
                    K.STR, K.NUM, K.ID -> meta[key.text] = v.text
                    else -> throw IllegalStateException("bad meta value for ${key.text}")
                }
            }
        }

        // ------- strings section

        private fun parseStrings(lex: YaraLexer, out: MutableList<YString>) {
            while (!sectionAhead(lex)) {
                val idTok = lex.next()
                if (idTok.k != K.ID || !idTok.text.startsWith("$"))
                    throw IllegalStateException("expected '\$id' string id, got '${idTok.text}'")
                expectSym(lex, "=")
                val v = lex.nextValue()
                val mods = mutableSetOf<String>()
                while (lex.peek().k == K.ID && lex.peek().text in MODIFIERS) {
                    mods.add(lex.next().text)
                }
                out.add(buildString(idTok.text.substring(1), v, mods))
            }
        }

        private fun buildString(name: String, v: Tok, mods: Set<String>): YString {
            val fullword = "fullword" in mods
            val pattern: Pattern = when (v.k) {
                K.STR -> {
                    val bytes = if ("wide" in mods) v.text.toByteArray(Charsets.UTF_16LE)
                    else v.text.toByteArray(Charsets.UTF_8)
                    val flags = if ("nocase" in mods) Pattern.CASE_INSENSITIVE else 0
                    Pattern.compile(Pattern.quote(String(bytes, Charsets.ISO_8859_1)), flags)
                }
                K.HEX -> Pattern.compile(hexToRegex(v.text), Pattern.DOTALL)
                K.RX -> {
                    val flags = if ("nocase" in mods || 'i' in v.flags) Pattern.CASE_INSENSITIVE else 0
                    Pattern.compile(v.text, flags)
                }
                else -> throw IllegalStateException("bad string value for '\$$name'")
            }
            return YString(name, pattern, v.text, fullword)
        }

        /** Convert a YARA hex pattern (bytes, ?? and nibble wildcards) to a
         *  regex matching byte values viewed as ISO-8859-1 chars. */
        private fun hexToRegex(hex: String): String {
            val sb = StringBuilder()
            val tokens = hex.split(Regex("\\s+")).filter { it.isNotEmpty() }
            for (t in tokens) {
                when {
                    t == "??" -> sb.append("[\\s\\S]")
                    t.length == 2 && t[0].isHexDigit() && t[1].isHexDigit() ->
                        sb.append("\\x{").append(t.uppercase()).append('}')
                    t.length == 2 && t[0].isHexDigit() && t[1] == '?' ->
                        sb.append("[\\x{").append(t[0].uppercaseChar()).append("0}-\\x{")
                            .append(t[0].uppercaseChar()).append("F}]")
                    t.length == 2 && t[0] == '?' && t[1].isHexDigit() -> {
                        val lo = t[1].digitToInt(16)
                        sb.append('[')
                        for (hi in 0..15) {
                            sb.append("\\x{").append("%X".format(hi * 16 + lo)).append('}')
                        }
                        sb.append(']')
                    }
                    else -> throw IllegalStateException(
                        "unsupported hex token '$t' (jumps/xor not supported in YARA-lite)"
                    )
                }
            }
            if (sb.isEmpty()) throw IllegalStateException("empty hex pattern")
            return sb.toString()
        }

        // ------- condition expression parser

        private fun parseOr(lex: YaraLexer, strings: List<YString>): YCond {
            val list = mutableListOf(parseAnd(lex, strings))
            while (peekIs(lex, "or")) { lex.next(); list.add(parseAnd(lex, strings)) }
            return if (list.size == 1) list[0] else YCond.Or(list)
        }

        private fun parseAnd(lex: YaraLexer, strings: List<YString>): YCond {
            val list = mutableListOf(parseUnary(lex, strings))
            while (peekIs(lex, "and")) { lex.next(); list.add(parseUnary(lex, strings)) }
            return if (list.size == 1) list[0] else YCond.And(list)
        }

        private fun parseUnary(lex: YaraLexer, strings: List<YString>): YCond {
            if (peekIs(lex, "not")) { lex.next(); return YCond.Not(parseUnary(lex, strings)) }
            return parsePrimary(lex, strings)
        }

        private fun parsePrimary(lex: YaraLexer, strings: List<YString>): YCond {
            val atom = parseAtom(lex, strings)
            val p = lex.peek()
            if (p.k == K.SYM && p.text in setOf("=", "==", "!=", "<", "<=", ">", ">=")) {
                lex.next()
                val right = parseAtom(lex, strings)
                val op = if (p.text == "=") "==" else p.text
                return YCond.Cmp(atom, op, right)
            }
            return atom
        }

        private fun parseAtom(lex: YaraLexer, strings: List<YString>): YCond {
            val t = lex.next()
            return when {
                t.k == K.SYM && t.text == "(" -> {
                    val e = parseOr(lex, strings)
                    expectSym(lex, ")")
                    e
                }
                t.k == K.ID && (t.text == "any" || t.text == "all") -> {
                    expectId(lex, "of")
                    YCond.Quantified(t.text, parseOfTarget(lex, strings))
                }
                t.k == K.NUM -> {
                    if (peekIs(lex, "of")) {
                        lex.next()
                        YCond.Quantified(num(t.text).toString(), parseOfTarget(lex, strings))
                    } else YCond.IntLit(num(t.text))
                }
                t.k == K.ID && t.text == "true" -> YCond.BoolLit(true)
                t.k == K.ID && t.text == "false" -> YCond.BoolLit(false)
                t.k == K.ID && t.text == "filesize" -> YCond.FileSize
                t.k == K.ID && t.text.startsWith("#") -> YCond.CountRef(t.text.substring(1))
                t.k == K.ID && t.text.startsWith("@") -> YCond.OffsetRef(t.text.substring(1))
                t.k == K.ID && t.text.startsWith("$") -> YCond.StrRef(t.text.substring(1))
                else -> throw IllegalStateException("unexpected condition token '${t.text}'")
            }
        }

        private fun parseOfTarget(lex: YaraLexer, strings: List<YString>): List<String> {
            val t = lex.next()
            if (t.k == K.ID && t.text == "them") return strings.map { it.id }
            if (t.k == K.SYM && t.text == "(") {
                val ids = mutableListOf<String>()
                while (true) {
                    val e = lex.next()
                    if (e.k == K.SYM && e.text == ")") break
                    if (e.k != K.ID || !e.text.startsWith("$"))
                        throw IllegalStateException("bad string selector '${e.text}'")
                    val base = e.text.substring(1)
                    if (lex.peek().k == K.SYM && lex.peek().text == "*") {
                        lex.next()
                        val expanded = strings.filter { it.id.startsWith(base) }.map { it.id }
                        if (expanded.isEmpty())
                            throw IllegalStateException("no strings match '\${$base*}'")
                        ids.addAll(expanded)
                    } else {
                        if (strings.none { it.id == base })
                            throw IllegalStateException("unknown string '\$$base'")
                        ids.add(base)
                    }
                }
                return ids.distinct()
            }
            throw IllegalStateException("expected 'them' or a list after 'of'")
        }

        private fun peekIs(lex: YaraLexer, kw: String): Boolean {
            val t = lex.peek()
            return t.k == K.ID && t.text == kw
        }

        private fun expectId(lex: YaraLexer, kw: String) {
            val t = lex.next()
            if (t.k != K.ID || t.text != kw)
                throw IllegalStateException("expected '$kw', got '${t.text}'")
        }

        private fun expectSym(lex: YaraLexer, sym: String) {
            val t = lex.next()
            if (t.k != K.SYM || t.text != sym)
                throw IllegalStateException("expected '$sym', got '${t.text}'")
        }

        private fun num(s: String): Long =
            if (s.startsWith("0x") || s.startsWith("0X")) s.substring(2).toLong(16)
            else s.toLong()
    }

    // ------------------------------------------------ condition evaluation

    private object YCondEval {
        fun isTrue(c: YCond, ctx: Ctx): Boolean = evalBool(c, ctx)

        private fun evalBool(c: YCond, ctx: Ctx): Boolean = when (c) {
            is YCond.StrRef -> ctx.matches[c.id]?.isNotEmpty() == true
            is YCond.BoolLit -> c.v
            is YCond.And -> c.l.all { evalBool(it, ctx) }
            is YCond.Or -> c.l.any { evalBool(it, ctx) }
            is YCond.Not -> !evalBool(c.c, ctx)
            is YCond.Cmp -> cmp(evalNum(c.left, ctx), c.op, evalNum(c.right, ctx))
            is YCond.Quantified -> {
                val hits = c.ids.count { ctx.matches[it]?.isNotEmpty() == true }
                when (c.quant) {
                    "any" -> hits >= 1
                    "all" -> hits == c.ids.size
                    else -> hits >= (c.quant.toLongOrNull() ?: 0L)
                }
            }
            is YCond.CountRef -> (ctx.matches[c.id]?.size ?: 0) != 0
            is YCond.OffsetRef -> (ctx.matches[c.id]?.firstOrNull() ?: -1L) >= 0
            is YCond.FileSize -> ctx.data.isNotEmpty()
            is YCond.IntLit -> c.v != 0L
        }

        private fun cmp(l: Long, op: String, r: Long): Boolean = when (op) {
            "==", "=" -> l == r
            "!=" -> l != r
            "<" -> l < r
            "<=" -> l <= r
            ">" -> l > r
            ">=" -> l >= r
            else -> false
        }

        private fun evalNum(c: YCond, ctx: Ctx): Long = when (c) {
            is YCond.IntLit -> c.v
            is YCond.CountRef -> (ctx.matches[c.id]?.size ?: 0).toLong()
            is YCond.OffsetRef -> ctx.matches[c.id]?.firstOrNull() ?: -1L
            is YCond.FileSize -> ctx.data.size.toLong()
            is YCond.StrRef -> if (ctx.matches[c.id]?.isNotEmpty() == true) 1L else 0L
            is YCond.BoolLit -> if (c.v) 1L else 0L
            is YCond.Cmp -> if (evalBool(c, ctx)) 1L else 0L
            is YCond.Quantified -> if (evalBool(c, ctx)) 1L else 0L
            is YCond.And -> if (evalBool(c, ctx)) 1L else 0L
            is YCond.Or -> if (evalBool(c, ctx)) 1L else 0L
            is YCond.Not -> if (evalBool(c, ctx)) 1L else 0L
        }
    }
}
