package com.ecrew.protocol

import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.Base64

/**
 * Result of processing a plaintext `hello` frame on the agent side.
 */
sealed class HandshakeOutcome {
    /** Code accepted; session key derived. */
    class Accepted(
        val sessionKey: ByteArray,
        val salt: ByteArray,
        val model: String?,
        val ver: String?
    ) : HandshakeOutcome()

    /** Wrong code but attempts remain (send auth_fail, close socket, a new attempt is allowed). */
    class RejectedRetryable(val reason: String) : HandshakeOutcome()

    /** No further attempts ever (burned after 3 failures / protocol violation). */
    class RejectedFatal(val reason: String) : HandshakeOutcome()

    /** Attempt arrived faster than the rate limit; not counted. */
    class RateLimited(val waitMs: Long) : HandshakeOutcome()
}

/**
 * Agent-side (Device2) handshake state machine.
 *
 * State intentionally persists across TCP/BT connection attempts so the 3-attempt burn and
 * the 1-attempt-per-2-seconds rate limit hold across reconnects. Create ONE instance per
 * pairing-code lifetime (i.e., per consent flow), not per connection.
 *
 * Not thread-safe: callers must guard with their own lock (a session accept loop is serial
 * by design).
 */
class HandshakeServer(
    private val expectedCode: String,
    private val clock: () -> Long = System::currentTimeMillis
) {

    private var attempts = 0
    private var banned = false
    private var lastAttemptAt: Long? = null

    /** True once a hello was accepted (no further hello frames may be processed). */
    var authenticated: Boolean = false
        private set

    /** Test/status accessor. */
    val attemptCount: Int get() = attempts

    val isBanned: Boolean get() = banned

    fun onHello(message: Map<String, Any?>): HandshakeOutcome {
        if (banned) return HandshakeOutcome.RejectedFatal("too many attempts")
        if (authenticated) return HandshakeOutcome.RejectedFatal("hello after auth_ok")

        val now = clock()
        val last = lastAttemptAt
        if (last != null) {
            val elapsed = now - last
            if (elapsed < ProtocolConstants.RATE_LIMIT_MS) {
                return HandshakeOutcome.RateLimited(ProtocolConstants.RATE_LIMIT_MS - elapsed)
            }
        }
        lastAttemptAt = now

        val code = Messages.string(message, "code")
        val saltB64 = Messages.string(message, "salt")
        val salt = try {
            if (saltB64 == null) null else Base64.getDecoder().decode(saltB64)
        } catch (e: IllegalArgumentException) {
            null
        }

        if (code == null || salt == null || salt.size != KeyDerivation.SALT_BYTES) {
            // Malformed hello counts as a failed attempt (defensive).
            return registerFailure("malformed hello")
        }
        if (code != expectedCode) {
            return registerFailure("invalid code")
        }

        val key = KeyDerivation.deriveKey(code, salt)
        authenticated = true
        return HandshakeOutcome.Accepted(
            sessionKey = key,
            salt = salt,
            model = Messages.string(message, "model"),
            ver = Messages.string(message, "ver")
        )
    }

    private fun registerFailure(reason: String): HandshakeOutcome {
        attempts += 1
        return if (attempts >= ProtocolConstants.MAX_ATTEMPTS) {
            banned = true
            HandshakeOutcome.RejectedFatal(reason)
        } else {
            HandshakeOutcome.RejectedRetryable(reason)
        }
    }
}

/**
 * Controller-side (Device1) handshake helper over a plaintext stream pair.
 *
 * Writes `hello` (length-prefixed JSON), waits for `auth_ok`/`auth_fail`, derives and
 * returns the session key plus the agent-assigned session id on success.
 * Callers own socket timeouts.
 */
object HandshakeClient {

    /** Successful handshake: derived key plus what the agent reported in `auth_ok`. */
    class Result(
        val sessionKey: ByteArray,
        val sessionId: String?
    )

    class HandshakeFailedException(reason: String) : Exception(reason)

    fun perform(
        input: DataInputStream,
        output: DataOutputStream,
        code: String,
        model: String,
        ver: String = ProtocolConstants.VERSION,
        salt: ByteArray = KeyDerivation.randomSalt()
    ): Result {
        require(salt.size == KeyDerivation.SALT_BYTES) { "salt must be ${KeyDerivation.SALT_BYTES} bytes" }
        val hello = Messages.hello(
            code = code,
            saltB64 = Base64.getEncoder().encodeToString(salt),
            model = model,
            ver = ver,
            ts = System.currentTimeMillis()
        )
        Frames.writePlain(output, hello)
        val reply = Frames.readPlain(input, ProtocolConstants.MAX_HANDSHAKE_BYTES)
        return when (Messages.type(reply)) {
            Msg.AUTH_OK -> Result(
                sessionKey = KeyDerivation.deriveKey(code, salt),
                sessionId = Messages.string(reply, "sessionId")
            )
            Msg.AUTH_FAIL -> throw HandshakeFailedException(Messages.string(reply, "reason") ?: "rejected")
            else -> throw HandshakeFailedException("unexpected handshake reply")
        }
    }
}
