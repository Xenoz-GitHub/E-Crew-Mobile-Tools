package com.ecrew.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * Handshake policy tests: correct code accepted, three wrong attempts burn the code,
 * a correct code after the burn is rejected, rate limiting (2 s) does not count as an
 * attempt, and hello is only allowed as the first frame.
 */
class HandshakeTest {

    private var now = 10_000L
    private val clock: () -> Long = { now }

    private fun server(code: String = CODE) = HandshakeServer(code, clock)

    private fun hello(code: String, salt: ByteArray = ByteArray(KeyDerivation.SALT_BYTES) { 7 }) =
        Messages.hello(
            code = code,
            saltB64 = Base64.getEncoder().encodeToString(salt),
            model = "Test Model",
            ver = ProtocolConstants.VERSION,
            ts = now
        )

    @Test
    fun correctCodeSucceeds() {
        val outcome = server().onHello(hello(CODE))
        assertTrue(outcome is HandshakeOutcome.Accepted)
        val accepted = outcome as HandshakeOutcome.Accepted
        assertEquals(KeyDerivation.KEY_BYTES, accepted.sessionKey.size)
        assertEquals(KeyDerivation.SALT_BYTES, accepted.salt.size)
        assertEquals("Test Model", accepted.model)
    }

    @Test
    fun wrongCodeFailsAfterThreeAttempts() {
        val server = server()

        val first = server.onHello(hello("000000"))
        assertTrue(first is HandshakeOutcome.RejectedRetryable)
        assertEquals(1, server.attemptCount)

        now += ProtocolConstants.RATE_LIMIT_MS
        val second = server.onHello(hello("000001"))
        assertTrue(second is HandshakeOutcome.RejectedRetryable)
        assertEquals(2, server.attemptCount)

        now += ProtocolConstants.RATE_LIMIT_MS
        val third = server.onHello(hello("000002"))
        assertTrue(third is HandshakeOutcome.RejectedFatal)

        assertEquals(3, server.attemptCount)
        assertTrue(server.isBanned)

        // "correct code after 3 failures is rejected"
        now += ProtocolConstants.RATE_LIMIT_MS
        val afterBurn = server.onHello(hello(CODE))
        assertTrue(afterBurn is HandshakeOutcome.RejectedFatal)
    }

    @Test
    fun rateLimitedAttemptIsNotCounted() {
        val server = server()

        val first = server.onHello(hello("999999"))
        assertTrue(first is HandshakeOutcome.RejectedRetryable)
        assertEquals(1, server.attemptCount)

        // Too fast: refused without counting.
        now += 500
        val tooFast = server.onHello(hello(CODE))
        assertTrue(tooFast is HandshakeOutcome.RateLimited)
        assertEquals(1, server.attemptCount)

        // After the rate limit window elapses the correct code still works.
        now += ProtocolConstants.RATE_LIMIT_MS
        val accepted = server.onHello(hello(CODE))
        assertTrue(accepted is HandshakeOutcome.Accepted)
        assertFalse(server.isBanned)
    }

    @Test
    fun helloAfterAuthRejected() {
        val server = server()
        assertTrue(server.onHello(hello(CODE)) is HandshakeOutcome.Accepted)
        now += ProtocolConstants.RATE_LIMIT_MS
        val again = server.onHello(hello(CODE))
        assertTrue(again is HandshakeOutcome.RejectedFatal)
    }

    @Test
    fun malformedHelloCountsAsFailedAttempt() {
        val server = server()
        val outcome = server.onHello(mapOf("t" to Msg.HELLO, "code" to "123456"))
        assertTrue(outcome is HandshakeOutcome.RejectedRetryable)
        assertEquals(1, server.attemptCount)
    }

    private companion object {
        const val CODE = "123456"
    }
}
