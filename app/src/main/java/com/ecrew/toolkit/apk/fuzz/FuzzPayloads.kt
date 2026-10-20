package com.ecrew.toolkit.apk.fuzz

/** Where a fuzz value is applied. */
enum class FuzzChannel {
    INTENT_EXTRA,
    INTENT_ACTION,
    INTENT_DATA,
    PROVIDER_PROJECTION,
    PROVIDER_SELECTION,
    PROVIDER_INSERT,
    BROADCAST_EXTRA
}

/**
 * One fixed, non-user-supplied payload. Audit records store only [id], never [value].
 * The long string is materialized once; every scanner and intent copies it, so it is kept at
 * the prompt's 1e6-character ceiling rather than an unbounded length.
 */
data class FuzzPayload(
    val id: String,
    val label: String,
    val channel: FuzzChannel,
    val value: String
)

object FuzzPayloads {
    const val LONG_STRING_LENGTH = 1_000_000

    private val longString by lazy { "A".repeat(LONG_STRING_LENGTH) }

    val intentPayloads: List<FuzzPayload> = listOf(
        FuzzPayload("format_string", "Format-string specifiers", FuzzChannel.INTENT_EXTRA, "%s%s%s%n"),
        FuzzPayload(
            "path_traversal",
            "Path traversal",
            FuzzChannel.INTENT_EXTRA,
            "../../../../../../etc/passwd"
        ),
        FuzzPayload("null_byte", "Embedded null byte", FuzzChannel.INTENT_EXTRA, "safe\u0000evil"),
        FuzzPayload(
            "int_as_string",
            "Integer boundary as string",
            FuzzChannel.INTENT_EXTRA,
            "2147483647"
        ),
        FuzzPayload("bool_as_string", "Boolean as string", FuzzChannel.INTENT_EXTRA, "true"),
        FuzzPayload(
            "uri_as_string",
            "Content URI as string",
            FuzzChannel.INTENT_EXTRA,
            "content://com.example.target/../../etc/passwd"
        ),
        FuzzPayload("long_string", "One-million-character string", FuzzChannel.INTENT_EXTRA, longString),
        FuzzPayload("empty_string", "Empty string", FuzzChannel.INTENT_EXTRA, "")
    )

    val actionPayloads: List<FuzzPayload> = listOf(
        FuzzPayload("action_view", "VIEW action", FuzzChannel.INTENT_ACTION, "android.intent.action.VIEW"),
        FuzzPayload(
            "action_send",
            "SEND action",
            FuzzChannel.INTENT_ACTION,
            "android.intent.action.SEND"
        ),
        FuzzPayload(
            "action_boot",
            "BOOT_COMPLETED action",
            FuzzChannel.INTENT_ACTION,
            "android.intent.action.BOOT_COMPLETED"
        )
    )

    val dataPayloads: List<FuzzPayload> = listOf(
        FuzzPayload(
            "data_traversal",
            "Traversal data URI",
            FuzzChannel.INTENT_DATA,
            "content://com.example.target/../../../../etc/passwd"
        ),
        FuzzPayload(
            "data_file",
            "File data URI",
            FuzzChannel.INTENT_DATA,
            "file:///data/local/tmp/ecrew-probe"
        )
    )

    val providerQueryPayloads: List<FuzzPayload> = listOf(
        FuzzPayload("sqli_error", "Error-based SQL injection", FuzzChannel.PROVIDER_SELECTION, "'"),
        FuzzPayload(
            "sqli_boolean",
            "Boolean SQL injection",
            FuzzChannel.PROVIDER_SELECTION,
            "1 OR 1=1"
        ),
        FuzzPayload(
            "sqli_union",
            "UNION SQL injection",
            FuzzChannel.PROVIDER_SELECTION,
            "1 UNION SELECT NULL,NULL--"
        ),
        FuzzPayload(
            "sqli_time",
            "Time-based SQL injection",
            FuzzChannel.PROVIDER_SELECTION,
            "1) OR SLEEP(2)--"
        ),
        FuzzPayload(
            "provider_traversal",
            "Provider path traversal",
            FuzzChannel.PROVIDER_PROJECTION,
            "../../../../etc/passwd"
        )
    )

    val providerInsertPayloads: List<FuzzPayload> = listOf(
        FuzzPayload("insert_sqli", "Insert SQL payload", FuzzChannel.PROVIDER_INSERT, "' OR 1=1--"),
        FuzzPayload(
            "insert_long",
            "Insert long value",
            FuzzChannel.PROVIDER_INSERT,
            longString
        )
    )

    val broadcastPayloads: List<FuzzPayload> = listOf(
        FuzzPayload(
            "broadcast_auth",
            "Authentication bypass category",
            FuzzChannel.BROADCAST_EXTRA,
            "com.ecrew.fuzz.AUTH_BYPASS"
        ),
        FuzzPayload(
            "broadcast_sqli",
            "SQL injection category",
            FuzzChannel.BROADCAST_EXTRA,
            "com.ecrew.fuzz.SQLI"
        ),
        FuzzPayload(
            "broadcast_lfi",
            "Local file inclusion category",
            FuzzChannel.BROADCAST_EXTRA,
            "com.ecrew.fuzz.LFI"
        ),
        FuzzPayload(
            "broadcast_redirect",
            "Open redirect category",
            FuzzChannel.BROADCAST_EXTRA,
            "com.ecrew.fuzz.REDIRECT"
        ),
        FuzzPayload(
            "broadcast_privesc",
            "Privilege escalation category",
            FuzzChannel.BROADCAST_EXTRA,
            "com.ecrew.fuzz.PRIVESC"
        ),
        FuzzPayload(
            "broadcast_exfil",
            "Data exfiltration category",
            FuzzChannel.BROADCAST_EXTRA,
            "com.ecrew.fuzz.EXFIL"
        )
    )

    fun all(channel: FuzzChannel): List<FuzzPayload> =
        (intentPayloads + actionPayloads + dataPayloads + providerQueryPayloads +
            providerInsertPayloads + broadcastPayloads)
            .filter { it.channel == channel }
}
