package com.ecrew.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import kotlin.concurrent.thread

/**
 * Loopback tests for [HandshakeClient]: the client side of the handshake had no coverage
 * before the Remote Support controller needed its session id (F5 addition).
 */
class HandshakeClientTest {

    private class Loopback(code: String) {
        val clientInput: DataInputStream
        val clientOutput: DataOutputStream
        val server: HandshakeServer
        val serverThread: Thread

        init {
            // client -> server
            val clientToServerOut = PipedOutputStream()
            val serverInput = PipedInputStream(clientToServerOut)
            // server -> client
            val serverToClientOut = PipedOutputStream()
            val clientInputRaw = PipedInputStream(serverToClientOut)

            clientInput = DataInputStream(clientInputRaw)
            clientOutput = DataOutputStream(clientToServerOut)
            server = HandshakeServer(code)

            serverThread = thread(name = "loopback-server") {
                runCatching {
                    val hello = Frames.readPlain(DataInputStream(serverInput), ProtocolConstants.MAX_HANDSHAKE_BYTES)
                    val outcome = server.onHello(hello)
                    if (outcome is HandshakeOutcome.Accepted) {
                        Frames.writePlain(DataOutputStream(serverToClientOut), Messages.authOk("sess-42"))
                    } else {
                        Frames.writePlain(DataOutputStream(serverToClientOut), Messages.authFail("rejected"))
                    }
                }
            }
        }
    }

    @Test
    fun successfulHandshakeReturnsKeyAndSessionId() {
        val salt = ByteArray(KeyDerivation.SALT_BYTES) { 9 }
        val loop = Loopback("123456")
        val result = HandshakeClient.perform(
            loop.clientInput, loop.clientOutput, "123456", "controller", salt = salt
        )
        assertEquals("sess-42", result.sessionId)
        assertTrue(result.sessionKey.contentEquals(KeyDerivation.deriveKey("123456", salt)))
        loop.serverThread.join(5_000)
    }

    @Test
    fun wrongCodeThrowsHandshakeFailed() {
        val loop = Loopback("123456")
        val failure = runCatching {
            HandshakeClient.perform(
                loop.clientInput, loop.clientOutput, "000000", "controller",
                salt = ByteArray(KeyDerivation.SALT_BYTES) { 3 }
            )
        }.exceptionOrNull()
        assertTrue(failure is HandshakeClient.HandshakeFailedException)
        loop.serverThread.join(5_000)
    }
}
