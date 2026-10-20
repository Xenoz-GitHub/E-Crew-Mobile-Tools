package com.ecrew.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Additive v1 extension tests: app-list request/response framing, defensive parsing, caps,
 * sanitization, sorting, and wire-size bounds.
 */
class AppInventoryTest {

    private fun entry(index: Int, system: Boolean = false) = AppInventory.Entry(
        packageName = "com.example.app$index",
        label = "App $index",
        version = "1.$index",
        system = system
    )

    @Test
    fun requestHasExpectedType() {
        val message = Messages.appListRequest()
        assertEquals(Msg.APP_LIST_REQ, Messages.type(message))
        assertEquals(1, message.size)
    }

    @Test
    fun wireRoundTripPreservesEntries() {
        val snapshot = AppInventory.Snapshot(
            entries = listOf(
                AppInventory.Entry("com.example.alpha", "Alpha", "1.2.3", false),
                AppInventory.Entry("com.android.settings", "Settings", null, true)
            ),
            total = 2,
            truncated = false
        )
        val encoded = Json.encode(AppInventory.toMessage(snapshot))
        val decoded = Json.parse(encoded)
        assertEquals(Msg.APP_LIST, Messages.type(decoded))

        val parsed = AppInventory.parse(decoded)
        requireNotNull(parsed)
        assertEquals(2, parsed.entries.size)
        assertEquals("Alpha", parsed.entries[0].label)
        assertEquals("1.2.3", parsed.entries[0].version)
        assertFalse(parsed.entries[0].system)
        assertNull(parsed.entries[1].version)
        assertTrue(parsed.entries[1].system)
        assertEquals(2, parsed.total)
        assertFalse(parsed.truncated)
    }

    @Test
    fun encoderCapsEntriesAndFlagsTruncation() {
        val entries = (0 until AppInventory.MAX_ENTRIES + 25).map { entry(it) }
        val wire = AppInventory.toMessage(AppInventory.Snapshot(entries, entries.size, false))
        val parsed = AppInventory.parse(Json.parse(Json.encode(wire)))
        requireNotNull(parsed)
        assertEquals(AppInventory.MAX_ENTRIES, parsed.entries.size)
        assertEquals(entries.size, parsed.total)
        assertTrue(parsed.truncated)
    }

    @Test
    fun parserCapsPeerProvidedListAtLimit() {
        val apps = (0 until AppInventory.MAX_ENTRIES + 200).map { index ->
            mapOf(
                "pkg" to "com.peer.app$index",
                "label" to "Peer app $index",
                "ver" to "1.0",
                "sys" to false
            )
        }
        val parsed = AppInventory.parse(
            mapOf(
                "t" to Msg.APP_LIST,
                "apps" to apps,
                "total" to apps.size.toLong(),
                "truncated" to false
            )
        )
        requireNotNull(parsed)
        assertEquals(AppInventory.MAX_ENTRIES, parsed.entries.size)
        assertEquals(apps.size, parsed.total)
        assertTrue(parsed.truncated)
    }

    @Test
    fun parserSanitizesFieldsAndSkipsMalformedEntries() {
        val parsed = AppInventory.parse(
            mapOf(
                "t" to Msg.APP_LIST,
                "apps" to listOf(
                    mapOf("pkg" to "  com.good  ", "label" to "Good\nApp", "ver" to " 1.0 ", "sys" to false),
                    mapOf("pkg" to "com.good", "label" to "duplicate package"),
                    mapOf("label" to "missing package"),
                    mapOf("pkg" to 42),
                    "not a map",
                    mapOf(
                        "pkg" to "com.bad",
                        "label" to "x".repeat(AppInventory.MAX_LABEL_CHARS + 50),
                        "ver" to "v".repeat(AppInventory.MAX_VERSION_CHARS + 10),
                        "sys" to "yes"
                    )
                ),
                "total" to 6L
            )
        )
        requireNotNull(parsed)
        assertEquals(2, parsed.entries.size)
        assertEquals("com.good", parsed.entries[0].packageName)
        assertEquals("GoodApp", parsed.entries[0].label)
        assertEquals("1.0", parsed.entries[0].version)
        assertFalse(parsed.entries[0].system)
        assertEquals(AppInventory.MAX_LABEL_CHARS, parsed.entries[1].label.length)
        assertEquals(AppInventory.MAX_VERSION_CHARS, parsed.entries[1].version?.length)
        assertFalse(parsed.entries[1].system)
        assertTrue("skipped entries must mark the response truncated", parsed.truncated)
    }

    @Test
    fun parserRejectsWrongTypeOrMissingArray() {
        assertNull(AppInventory.parse(mapOf("t" to Msg.APP_LIST_REQ)))
        assertNull(AppInventory.parse(mapOf("t" to Msg.APP_LIST, "apps" to "not a list")))
        assertNull(AppInventory.parse(mapOf("t" to Msg.APP_LIST)))
    }

    @Test
    fun parserAcceptsEmptyInventory() {
        val parsed = AppInventory.parse(
            mapOf("t" to Msg.APP_LIST, "apps" to emptyList<Any?>(), "total" to 0L)
        )
        requireNotNull(parsed)
        assertTrue(parsed.entries.isEmpty())
        assertEquals(0, parsed.total)
        assertFalse(parsed.truncated)
    }

    @Test
    fun sortedForDisplayPutsUserAppsFirstThenLabel() {
        val sorted = AppInventory.sortedForDisplay(
            listOf(
                AppInventory.Entry("com.z.system", "Zeta", "1", true),
                AppInventory.Entry("com.b.user", "beta", "1", false),
                AppInventory.Entry("com.a.user", "Alpha", "1", false)
            )
        )
        assertEquals(
            listOf("com.a.user", "com.b.user", "com.z.system"),
            sorted.map { it.packageName }
        )
    }

    @Test
    fun encodedInventoryStaysFarBelowFrameCap() {
        val entries = (0 until AppInventory.MAX_ENTRIES).map {
            AppInventory.Entry(
                packageName = "p".repeat(AppInventory.MAX_PACKAGE_CHARS),
                label = "l".repeat(AppInventory.MAX_LABEL_CHARS),
                version = "v".repeat(AppInventory.MAX_VERSION_CHARS),
                system = false
            )
        }
        val bytes = Json.encode(
            AppInventory.toMessage(AppInventory.Snapshot(entries, entries.size, false))
        ).toByteArray(Charsets.UTF_8).size
        assertTrue("inventory must stay below 1 MB, was $bytes", bytes < 1024 * 1024)
        assertTrue(bytes < ProtocolConstants.MAX_FRAME_BYTES)
    }
}
