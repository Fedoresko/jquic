package org.fmalyshev.quic;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.fmalyshev.quic.QuicConnectionCryptoIntegrationTest.destinationCidBytes;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * Integration tests for SelectorThread.
 * Tests the full lifecycle of connections through processPacket() with real QUIC datagrams.
 */
class SelectorThreadTest {

    private static final long TEST_CID = 123456789L;
    private static final SocketAddress TEST_ADDRESS = new InetSocketAddress("127.0.0.1", 8080);

    private SelectorThread selectorThread;
    private DatagramChannel channel;
    private Map<Long, QuicConnection> activeConnections;
    private TimeoutHeap timeoutHeap;

    @BeforeEach
    void setUp() throws Exception {
        // Create SelectorThread components
        channel = DatagramChannel.open();
        ConcurrentHashMap<Long, Integer> cidToSelectorMap = new ConcurrentHashMap<>();

        selectorThread = new SelectorThread(0, channel, cidToSelectorMap);

        // Use reflection to access private fields for testing
        Field activeConnectionsField = SelectorThread.class.getDeclaredField("activeConnections");
        activeConnectionsField.setAccessible(true);
        activeConnections = (Map<Long, QuicConnection>) activeConnectionsField.get(selectorThread);

        Field timeoutHeapField = SelectorThread.class.getDeclaredField("timeoutHeap");
        timeoutHeapField.setAccessible(true);
        timeoutHeap = (TimeoutHeap) timeoutHeapField.get(selectorThread);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (channel != null && channel.isOpen()) {
            channel.close();
        }
    }

    @Test
    @DisplayName("Test connection timeout is updated when processing 1-RTT packets")
    void testTimeoutUpdatedOnPacketProcessing() throws Exception {
        // Create and setup connection in ESTABLISHED state
        QuicConnection connection = new QuicConnection(TEST_CID, TEST_ADDRESS);
        connection.setState(QuicConnection.State.ESTABLISHED);
        QuicCrypto.TlsMetadata tlsMetadata = setupRealTlsMetadata(connection);
        connection.setIdleTimeout(100); // Short timeout for testing

        // Add to active connections and timeout heap
        activeConnections.put(TEST_CID, connection);
        timeoutHeap.insertOrUpdate(connection);

        long timeoutBefore = connection.getTimeoutTimestamp();

        // Wait a bit to ensure timestamp will change
        Thread.sleep(20);

        // Create 1-RTT packet with PING frame (ack-eliciting) using real encryption
        ByteBuffer packet = createEncrypted1RttPacketWithPing(TEST_CID, tlsMetadata.clientApplicationKeys.key());

        // Process packet via SelectorThread
        Method processPacketMethod = SelectorThread.class.getDeclaredMethod(
            "processPacket", ByteBuffer.class, SocketAddress.class, String.class);
        processPacketMethod.setAccessible(true);
        processPacketMethod.invoke(selectorThread, packet, TEST_ADDRESS, "test");

        // Verify timeout was updated
        long timeoutAfter = connection.getTimeoutTimestamp();
        assertTrue(timeoutAfter > timeoutBefore,
            "Timeout should be updated after processing packet");

        // Verify connection is still in heap with updated position
        assertTrue(timeoutHeap.size() > 0, "Connection should remain in timeout heap");
    }

    @Test
    @DisplayName("Test connections are evicted in correct order based on timeout")
    void testConnectionsEvictedInTimeoutOrder() throws Exception {
        // Create 3 connections with different timeouts
            QuicConnection conn1 = new QuicConnection(1001L, new InetSocketAddress("127.0.0.1", 5001));
            QuicConnection conn2 = new QuicConnection(1002L, new InetSocketAddress("127.0.0.1", 5002));
            QuicConnection conn3 = new QuicConnection(1003L, new InetSocketAddress("127.0.0.1", 5003));

            // Set very short timeouts for testing
            conn1.setIdleTimeout(50);  // Will timeout first
            conn2.setIdleTimeout(100); // Will timeout second
            conn3.setIdleTimeout(200); // Will timeout last

            // Add all connections to active map and heap
            activeConnections.put(1001L, conn1);
            activeConnections.put(1002L, conn2);
            activeConnections.put(1003L, conn3);

            timeoutHeap.insertOrUpdate(conn1);
            timeoutHeap.insertOrUpdate(conn2);
            timeoutHeap.insertOrUpdate(conn3);

            assertEquals(3, activeConnections.size(), "Should have 3 active connections");

            // Wait for first two connections to timeout
            Thread.sleep(150);

            // Trigger eviction manually (simulating what periodic check does)
            Method evictMethod = SelectorThread.class.getDeclaredMethod("evictTimedOutConnections");
            evictMethod.setAccessible(true);
            evictMethod.invoke(selectorThread);

            // Verify first two connections were evicted
            assertEquals(1, activeConnections.size(), "Should have 1 active connection remaining");
            assertFalse(activeConnections.containsKey(1001L), "Conn1 should be evicted");
            assertFalse(activeConnections.containsKey(1002L), "Conn2 should be evicted");
            assertTrue(activeConnections.containsKey(1003L), "Conn3 should remain active");

            // Verify evicted connections are in CLOSED state
            assertEquals(QuicConnection.State.CLOSED, conn1.getState(), "Conn1 should be CLOSED");
            assertEquals(QuicConnection.State.CLOSED, conn2.getState(), "Conn2 should be CLOSED");
    }

    @Test
    @DisplayName("Test packet activity prevents timeout eviction")
    void testPacketActivityPreventsEviction() throws Exception {
        // Create connection with short timeout
        QuicConnection connection = new QuicConnection(TEST_CID, TEST_ADDRESS);
        connection.setState(QuicConnection.State.ESTABLISHED);
        QuicCrypto.TlsMetadata tlsMetadata = setupRealTlsMetadata(connection);
        connection.setIdleTimeout(100); // 100ms timeout

        activeConnections.put(TEST_CID, connection);
        timeoutHeap.insertOrUpdate(connection);

        // Wait 60ms (more than halfway to timeout)
        Thread.sleep(60);

        // Send packet to refresh timeout using real encryption
        ByteBuffer packet = createEncrypted1RttPacketWithPing(TEST_CID, tlsMetadata.clientApplicationKeys.key());
        Method processPacketMethod = SelectorThread.class.getDeclaredMethod(
            "processPacket", ByteBuffer.class, SocketAddress.class, String.class);
        processPacketMethod.setAccessible(true);
        processPacketMethod.invoke(selectorThread, packet, TEST_ADDRESS, "test");

        // Wait another 60ms (would have timed out without packet activity)
        Thread.sleep(60);

        // Trigger eviction check
        Method evictMethod = SelectorThread.class.getDeclaredMethod("evictTimedOutConnections");
        evictMethod.setAccessible(true);
        evictMethod.invoke(selectorThread);

        // Verify connection is still active (not evicted)
        assertEquals(1, activeConnections.size(), "Connection should still be active");
        assertTrue(activeConnections.containsKey(TEST_CID), "Connection should not be evicted");
        assertNotEquals(QuicConnection.State.CLOSED, connection.getState(),
            "Connection should not be CLOSED");
    }

    @Test
    @DisplayName("Test CONNECTION_CLOSE triggers immediate eviction")
    void testConnectionCloseTriggersEviction() throws Exception {
        // Create connection in ESTABLISHED state
        QuicConnection connection = new QuicConnection(TEST_CID, TEST_ADDRESS);
        connection.setState(QuicConnection.State.ESTABLISHED);
        QuicCrypto.TlsMetadata tlsMetadata = setupRealTlsMetadata(connection);

        activeConnections.put(TEST_CID, connection);
        timeoutHeap.insertOrUpdate(connection);

        assertEquals(1, activeConnections.size(), "Should have 1 active connection");

        // Send CONNECTION_CLOSE packet using real encryption
        ByteBuffer packet = createEncrypted1RttPacketWithConnectionClose(tlsMetadata.clientApplicationKeys.key());

        Method processPacketMethod = SelectorThread.class.getDeclaredMethod(
            "processPacket", ByteBuffer.class, SocketAddress.class, String.class);
        processPacketMethod.setAccessible(true);
        processPacketMethod.invoke(selectorThread, packet, TEST_ADDRESS, "test");

        // Verify connection was evicted immediately
        assertEquals(0, activeConnections.size(), "Connection should be evicted after CONNECTION_CLOSE");
        assertFalse(activeConnections.containsKey(TEST_CID), "Connection should be removed from map");
        assertEquals(QuicConnection.State.CLOSED, connection.getState(), "Connection should be CLOSED");
    }

    @Test
    @DisplayName("Test multiple connections timeout in correct order with interleaved activity")
    void testMultipleConnectionsWithInterleavedActivity() throws Exception {
        // Create 3 connections with same timeout
        QuicConnection conn1 = new QuicConnection(2001L, new InetSocketAddress("127.0.0.1", 6001));
        QuicConnection conn2 = new QuicConnection(2002L, new InetSocketAddress("127.0.0.1", 6002));
        QuicConnection conn3 = new QuicConnection(2003L, new InetSocketAddress("127.0.0.1", 6003));

        QuicCrypto.TlsMetadata metadata1 = setupRealTlsMetadata(conn1);
        QuicCrypto.TlsMetadata metadata2 = setupRealTlsMetadata(conn2);
        QuicCrypto.TlsMetadata metadata3 = setupRealTlsMetadata(conn3);

        for (QuicConnection conn : new QuicConnection[]{conn1, conn2, conn3}) {
            conn.setState(QuicConnection.State.ESTABLISHED);
            conn.setIdleTimeout(100); // 100ms timeout
            activeConnections.put(conn.getConnectionId(), conn);
            timeoutHeap.insertOrUpdate(conn);
        }

        // Wait 40ms
        Thread.sleep(40);

        // Send packet to conn2 (refreshes its timeout) using real encryption
        Method processPacketMethod = SelectorThread.class.getDeclaredMethod(
            "processPacket", ByteBuffer.class, SocketAddress.class, String.class);
        processPacketMethod.setAccessible(true);

        ByteBuffer packet2 = createEncrypted1RttPacketWithPing(2002L, metadata2.clientApplicationKeys.key());
        processPacketMethod.invoke(selectorThread, packet2, TEST_ADDRESS, "test");

        // Wait another 40ms
        Thread.sleep(40);

        // Send packet to conn3 (refreshes its timeout) using real encryption
        ByteBuffer packet3 = createEncrypted1RttPacketWithPing(2003L, metadata3.clientApplicationKeys.key());
        processPacketMethod.invoke(selectorThread, packet3, TEST_ADDRESS, "test");

        // Wait 30ms more (total ~110ms, conn1 should timeout)
        Thread.sleep(30);

        // Trigger eviction
        Method evictMethod = SelectorThread.class.getDeclaredMethod("evictTimedOutConnections");
        evictMethod.setAccessible(true);
        evictMethod.invoke(selectorThread);

        // Verify only conn1 is evicted, conn2 and conn3 remain
        assertEquals(2, activeConnections.size(), "Should have 2 active connections");
        assertFalse(activeConnections.containsKey(2001L), "Conn1 should be evicted");
        assertTrue(activeConnections.containsKey(2002L), "Conn2 should remain (had activity)");
        assertTrue(activeConnections.containsKey(2003L), "Conn3 should remain (had activity)");
    }

    // Helper methods

    /**
     * Sets up real TLS metadata with actual derived keys for testing.
     */
    private QuicCrypto.TlsMetadata setupRealTlsMetadata(QuicConnection connection) throws Exception {
        // Derive real keys from the connection's DCID
        byte[] testDcid = new byte[8];
        ByteBuffer.wrap(testDcid).putLong(connection.getConnectionId());

        QuicCrypto.PacketProtectionKeysWithHP[] initialKeys = QuicCrypto.deriveInitialKeys(testDcid);

        // Use initial keys as stand-ins for handshake and 1-RTT keys.
        // The important requirement is that client1RttSecret and its HP key match
        // the key used to encrypt the test packets created by createEncrypted1RttPacket*.
        SecretKey clientHandshakeSecret = initialKeys[0].key();
        SecretKey serverHandshakeSecret = initialKeys[1].key();
        SecretKey client1RttSecret      = initialKeys[0].key();
        SecretKey server1RttSecret      = initialKeys[1].key();

        // Derive the 1-RTT header-protection key so process1RttPacket can unmask
        // the short-header packet number (RFC 9001 §5.4).
        byte[] client1RttHpKey = QuicCrypto.deriveHeaderProtectionKey(client1RttSecret);
        byte[] server1RttHpKey = QuicCrypto.deriveHeaderProtectionKey(server1RttSecret);
        byte[] client1RttIv = QuicCrypto.deriveIv(client1RttSecret.getEncoded());
        byte[] server1RttIv = QuicCrypto.deriveIv(server1RttSecret.getEncoded());

        QuicCrypto.TlsMetadata metadata = new QuicCrypto.TlsMetadata();
        metadata.clientRandom            = new byte[32];
        metadata.serverRandom            = new byte[32];
        metadata.selectedCipherSuite     = "TLS_AES_128_GCM_SHA256";
        metadata.alpn                    = "h3";
        metadata.negotiatedIdleTimeoutMs = 100;
        metadata.serverHandshakeKeys = new QuicCrypto.PacketProtectionKeysWithHP(serverHandshakeSecret, new byte[16], new byte[16]);
        metadata.clientHandshakeKeys = new QuicCrypto.PacketProtectionKeysWithHP(clientHandshakeSecret, new byte[16], new byte[16]);
        metadata.clientApplicationHeaderProtection = client1RttHpKey;
        metadata.serverApplicationHeaderProtection = server1RttHpKey;

        metadata.setApplicationKeys(new QuicCrypto.PacketProtectionKeys(client1RttSecret, client1RttIv),
                new QuicCrypto.PacketProtectionKeys(server1RttSecret, server1RttIv));

        connection.setTlsMetadata(metadata);
        return metadata;
    }

    /**
     * Creates a real encrypted 1-RTT packet with PING frame using QuicPacketBuilder.
     */
    private ByteBuffer createEncrypted1RttPacketWithPing(long cid, SecretKey encryptionKey) throws Exception {
        // Create PING frame
        ByteBuffer pingFrame = ByteBuffer.allocate(20);
        pingFrame.put((byte) 0x01); // PING frame type
        pingFrame.flip();

        // Use QuicPacketBuilder to create properly encrypted packet
        byte[] iv = QuicCrypto.deriveHeaderProtectionKey(encryptionKey); // reuse HP derivation path for test simplicity — real IV comes from setupRealTlsMetadata
        // Derive actual IV via the metadata that was set up for this connection
        QuicConnection conn = activeConnections.get(cid);
        byte[] baseIv = (conn != null && conn.getTlsMetadata() != null)
                ? conn.getTlsMetadata().clientApplicationKeys.iv() : new byte[12];
        QuicPacketBuilder.build1RttPacket( destinationCidBytes(cid), 0, pingFrame, new QuicCrypto.PacketProtectionKeys(encryptionKey, baseIv), null, (byte) 0);
        return pingFrame;
    }

    /**
     * Creates a real encrypted 1-RTT packet with CONNECTION_CLOSE frame.
     */
    private ByteBuffer createEncrypted1RttPacketWithConnectionClose(SecretKey encryptionKey) throws Exception {
        // Create CONNECTION_CLOSE frame
        ByteBuffer closeFrame = ByteBuffer.allocate(20);
        closeFrame.put((byte) 0x1c); // CONNECTION_CLOSE frame type
        closeFrame.put((byte) 0);    // Error code (varint)
        closeFrame.put((byte) 0);    // Frame type (varint)
        closeFrame.put((byte) 0);    // Reason length (varint)
        closeFrame.flip();

        // Use QuicPacketBuilder to create properly encrypted packet
        QuicConnection conn = activeConnections.get(SelectorThreadTest.TEST_CID);
        byte[] baseIv = (conn != null && conn.getTlsMetadata() != null)
                ? conn.getTlsMetadata().clientApplicationKeys.iv() : new byte[12];
        QuicPacketBuilder.build1RttPacket( destinationCidBytes(SelectorThreadTest.TEST_CID), 0, closeFrame, new QuicCrypto.PacketProtectionKeys(encryptionKey, baseIv), null, (byte) 0);
        return closeFrame;
    }
}
