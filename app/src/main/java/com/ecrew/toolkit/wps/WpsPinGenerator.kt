package com.ecrew.toolkit.wps

import java.util.Locale

/**
 * Ordered WPS PIN candidate generation for the vulnerability audit (owned networks only).
 *
 * Algorithms, per public documentation (citations in the design note):
 *  - Zhao (ZhaoChunsheng, 2012): the second half of the BSSID (last three bytes) as an
 *    integer, modulo 10 000 000, zero-padded to seven digits, plus the standard WPS
 *    checksum digit (as reproduced by the public PinAlgorithm reference and WPSPIN.sh).
 *  - Belkin (N900-class models): the same documented derivation on the same address bytes
 *    (exploit-db 38164, original work ZhaoChunsheng). Both algorithms agree on the value,
 *    so identical candidates are merged into one attempt that keeps both attributions.
 *    Newer Belkin DSL models derive the PIN from MAC + printed serial number (Stas'M
 *    universal algorithm), which cannot be computed from the BSSID alone and is
 *    deliberately out of scope (no serial-number guessing).
 *  - Fallback: commonly shipped static defaults - "12345670" plus the repeated-digit
 *    pattern family, ordered with the BSSID's own last digit first.
 *
 * Ordering: highest-probability source first (Zhao/Belkin, then fallback). Each algorithm
 * is capped at [MAX_PER_ALGORITHM] candidates; [WpsCandidates.capReached] tells the run
 * controller when the cap truncated a list so the audit can record "candidate cap
 * reached".
 */
data class WpsCandidate(
    val pin: String,
    val algorithms: List<String>
)

/** Ordered candidate list plus whether any algorithm was truncated at the cap. */
data class WpsCandidates(
    val list: List<WpsCandidate>,
    val capReached: Boolean
)

object WpsPinGenerator {

    const val MAX_PER_ALGORITHM = 10

    private const val ALGO_ZHAO = "Zhao"
    private const val ALGO_BELKIN = "Belkin"
    private const val ALGO_FALLBACK = "Fallback"

    private const val FIXED_DEFAULT_PIN = "12345670"

    /** Ordered, de-duplicated candidate list for [bssid] (empty if the address is malformed). */
    fun candidates(bssid: String): WpsCandidates {
        val hex = normalize(bssid) ?: return WpsCandidates(emptyList(), false)

        val ordered = mutableListOf<WpsCandidate>()

        // Zhao first (highest probability), then the Belkin N900-class derivation; both are
        // documented to compute the PIN from the same address bytes and therefore agree.
        val vendorPin = derivedPin(hex)
        mergeInto(ordered, vendorPin, ALGO_ZHAO)
        mergeInto(ordered, vendorPin, ALGO_BELKIN)

        val fallbackRaw = fallbackPins(hex)
        val fallback = capCandidates(fallbackRaw)
        for (pin in fallback) mergeInto(ordered, pin, ALGO_FALLBACK)

        return WpsCandidates(ordered, fallback.size < fallbackRaw.size)
    }

    /** Standard WPS PIN checksum: alternating 3/1 weights from the right. Visible for tests. */
    fun wpsChecksum(pin7: Int): Int {
        var value = pin7
        var accum = 0
        while (value > 0) {
            accum += 3 * (value % 10)
            value /= 10
            accum += value % 10
            value /= 10
        }
        return (10 - accum % 10) % 10
    }

    /**
     * True when [pin] is an 8-digit WPS PIN with the standard checksum. Router labels and
     * generated candidates both follow this format; rejecting malformed input before a
     * startWps call avoids an avoidable router-side failure.
     */
    fun isValidPin(pin: String): Boolean {
        if (pin.length != 8 || pin.any { it !in '0'..'9' }) return false
        val sevenDigits = pin.substring(0, 7).toInt()
        return pin.last() - '0' == wpsChecksum(sevenDigits)
    }

    /** Applies the per-algorithm candidate cap. Visible for tests. */
    internal fun capCandidates(raw: List<String>): List<String> = raw.take(MAX_PER_ALGORITHM)

    private fun normalize(bssid: String): String? {
        val hex = bssid.replace(":", "").replace("-", "").trim().uppercase()
        return if (hex.length == 12 && hex.all { it in "0123456789ABCDEF" }) hex else null
    }

    // Zhao (ZhaoChunsheng): last three BSSID bytes % 10^7, zero-padded, + WPS checksum.
    private fun derivedPin(hex: String): String {
        val secondHalf = hex.substring(6).toLong(16) % 10_000_000L
        val sevenDigits = secondHalf.toInt()
        return "%07d%d".format(Locale.US, sevenDigits, wpsChecksum(sevenDigits))
    }

    private fun fallbackPins(hex: String): List<String> {
        val lastChar = hex.last()
        val preferred = if (lastChar in '0'..'9') lastChar - '0' else -1
        val digits =
            if (preferred >= 0) listOf(preferred) + (0..9).filter { it != preferred }
            else (0..9).toList()
        val pins = mutableListOf(FIXED_DEFAULT_PIN)
        for (digit in digits) pins += digit.toString().repeat(8)
        return pins
    }

    private fun mergeInto(list: MutableList<WpsCandidate>, pin: String, algorithm: String) {
        val index = list.indexOfFirst { it.pin == pin }
        if (index >= 0) {
            list[index] = list[index].copy(algorithms = list[index].algorithms + algorithm)
        } else {
            list.add(WpsCandidate(pin, listOf(algorithm)))
        }
    }
}
