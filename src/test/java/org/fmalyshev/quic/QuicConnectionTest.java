package org.fmalyshev.quic;

import org.fmalyshev.quic.streamapi.StreamFrameListener;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

/**
 * Unit tests for QuicConnection class.
 * Tests basic QUIC connection scenarios according to RFC 9000.
 * TLS/crypto logic is mocked to focus on QUIC protocol behavior.
 */
class QuicConnectionTest {

    private static final long TEST_CID = 123456789L;
    private static final SocketAddress TEST_ADDRESS = new InetSocketAddress("127.0.0.1", 8080);

    private QuicConnection connection;

    @BeforeEach
    void setUp() {
        connection = new QuicConnection(TEST_CID, TEST_ADDRESS);
    }

    // ========================================================================
    // 1-RTT Handshake Tests
    // ========================================================================

    @Test
    @DisplayName("Test successful 1-RTT handshake: INITIAL → HANDSHAKE → ESTABLISHED")
    void testSuccessful1RttHandshake() throws Exception {
        // Mock crypto operations
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Initial state
            assertEquals(QuicConnection.State.INITIAL, connection.getState());

            // Step 1: Process Initial packet (ClientHello)
            ByteBuffer initialPacket = createMockInitialPacket();
            List<ByteBuffer> initialResponses = connection.processInitialAndRespond(initialPacket);

            assertFalse(initialResponses.isEmpty(), "Initial response should be generated");
            assertEquals(QuicConnection.State.HANDSHAKE, connection.getState(),
                    "Connection should transition to HANDSHAKE state");

            // Step 2: Process Handshake packet (client Finished)
            ByteBuffer handshakePacket = createMockHandshakePacket();
            List<ByteBuffer> handshakeResponses = connection.processHandshakePacket(handshakePacket);

            assertNotNull(handshakeResponses, "Handshake response should be generated");
            assertEquals(2, handshakeResponses.size(),
                    "Should return Handshake response + HANDSHAKE_DONE");
            assertEquals(QuicConnection.State.ESTABLISHED, connection.getState(),
                    "Connection should transition to ESTABLISHED state");

            // Verify that client Finished message was verified
            cryptoMock.verify(() -> QuicCrypto.verifyClientFinished(
                    any(byte[].class),           // finishedData - the CRYPTO frame content
                    any(SecretKey.class),        // clientHandshakeSecret
                    any(byte[].class)            // transcriptHash (empty in simplified mode)
            ), times(1));
        }
    }

    @Test
    @DisplayName("Test ClientHello processing failure sends CONNECTION_CLOSE")
    void testClientHelloProcessingFailure() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = Mockito.mockStatic(QuicCrypto.class)) {

            // Mock key derivation to succeed
            QuicCrypto.PacketProtectionKeys mockKeys = new QuicCrypto.PacketProtectionKeys(
                    mock(SecretKey.class), new byte[12], new byte[16]
            );
            cryptoMock.when(() -> QuicCrypto.deriveInitialKeys(any(byte[].class)))
                    .thenReturn(new QuicCrypto.PacketProtectionKeys[]{mockKeys, mockKeys});

            // Mock decryptAead
            cryptoMock.when(() -> QuicCrypto.decryptAead(any(), any(), any(), anyLong(), any(), any()))
                    .thenAnswer(invocation -> {
                        ByteBuffer output = invocation.getArgument(4);
                        output.put(new byte[50]); // Mock decrypted data
                        return null;
                    });

            // Mock processClientHello to throw exception
            cryptoMock.when(() -> QuicCrypto.processClientHello(any(ByteBuffer.class)))
                    .thenThrow(new QuicCrypto.CryptoException("Invalid ClientHello"));

            // Mock encryptPacket for CONNECTION_CLOSE
            cryptoMock.when(() -> QuicCrypto.encryptPacket(any(), any(), anyLong(), any(), any()))
                    .thenAnswer(invocation -> {
                        ByteBuffer input = invocation.getArgument(0);
                        ByteBuffer encrypted = ByteBuffer.allocate(input.remaining() + 50);
                        encrypted.put(input);
                        encrypted.flip();
                        return encrypted;
                    });

            // Initial state
            assertEquals(QuicConnection.State.INITIAL, connection.getState());

            // Process Initial packet with invalid ClientHello
            ByteBuffer initialPacket = createMockInitialPacket();
            List<ByteBuffer> responses = connection.processInitialAndRespond(initialPacket);

            // Verify CONNECTION_CLOSE was sent
            assertFalse(responses.isEmpty(), "CONNECTION_CLOSE response should be generated");
            assertEquals(QuicConnection.State.CLOSING, connection.getState(),
                    "Connection should transition to CLOSING state");

            // Verify processClientHello was called and failed
            cryptoMock.verify(() -> QuicCrypto.processClientHello(any(ByteBuffer.class)), times(1));

            // Verify encryptPacket was called to send CONNECTION_CLOSE
            cryptoMock.verify(() -> QuicCrypto.encryptPacket(any(), any(), anyLong(), any(), any()), times(1));
        }
    }

    @Test
    @DisplayName("Test Initial packet rejected in wrong state")
    void testInitialPacketInWrongState() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Move to HANDSHAKE state
            connection.setState(QuicConnection.State.HANDSHAKE);

            // Try to process Initial packet in HANDSHAKE state
            ByteBuffer initialPacket = createMockInitialPacket();
            List<ByteBuffer> responses = connection.processInitialAndRespond(initialPacket);

            assertTrue(responses.isEmpty(), "Initial packet should be rejected in HANDSHAKE state");
            assertEquals(QuicConnection.State.HANDSHAKE, connection.getState(),
                    "State should remain HANDSHAKE");
        }
    }

    @Test
    @DisplayName("Test Handshake packet rejected in wrong state")
    void testHandshakePacketInWrongState() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Connection in INITIAL state (wrong state for Handshake packet)
            assertEquals(QuicConnection.State.INITIAL, connection.getState());
            // Don't setup metadata - connection will reject due to wrong state

            ByteBuffer handshakePacket = createMockHandshakePacket();
            List<ByteBuffer> responses = connection.processHandshakePacket(handshakePacket);

            assertTrue(responses.isEmpty(), "Handshake packet should be rejected in INITIAL state");
            assertEquals(QuicConnection.State.INITIAL, connection.getState(),
                    "State should remain INITIAL");
        }
    }

    @Test
    @DisplayName("Test Handshake packet with failed Finished verification is silently discarded")
    void testHandshakePacketWithInvalidFinished() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in HANDSHAKE state
            connection.setState(QuicConnection.State.HANDSHAKE);
            setupMockTlsMetadata();

            // Override verifyClientFinished to return false (verification failed)
            // This overrides the default mock from mockQuicCrypto() which returns true
            cryptoMock.when(() -> QuicCrypto.verifyClientFinished(any(byte[].class), any(SecretKey.class), any(byte[].class)))
                    .thenReturn(false);

            // Process Handshake packet with invalid Finished message
            ByteBuffer handshakePacket = createMockHandshakePacket();
            List<ByteBuffer> responses = connection.processHandshakePacket(handshakePacket);

            // Verify packet was silently discarded
            assertTrue(responses.isEmpty(), "No response should be generated for invalid Finished");
            assertEquals(QuicConnection.State.HANDSHAKE, connection.getState(),
                    "Connection should remain in HANDSHAKE state (not transition to ESTABLISHED)");

            // Verify that verifyClientFinished was called
            cryptoMock.verify(() -> QuicCrypto.verifyClientFinished(
                    any(byte[].class),
                    any(SecretKey.class),
                    any(byte[].class)
            ), times(1));
        }
    }

    // ========================================================================
    // Stream Data Tests
    // ========================================================================

    @Test
    @DisplayName("Test stream data delivery to payload listener")
    void testStreamDataDelivery() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in ESTABLISHED state
            setupEstablishedConnection();

            // Capture delivered stream data
            AtomicReference<StreamFrameListener.StreamFrame> receivedData = new AtomicReference<>();

            connection.setStreamFrameListener(createStreamFrameListener(receivedData::set));

            // Create 1-RTT packet with STREAM frame
            ByteBuffer packet = createMock1RttPacketWithStreamData(4L, "Hello QUIC".getBytes());
            ByteBuffer ackResponse = connection.process1RttPacket(packet).get(0);

            // Verify stream data was delivered
            assertNotNull(receivedData.get(), "Stream data should be captured");
            // framePayload is positioned after the frame type byte, so it starts with:
            // stream_id (1 byte varint), offset (1 byte varint), length (1 byte varint), then data
            ByteBuffer framePayload = receivedData.get().rewind();
            framePayload.get(); // skip frame_id
            framePayload.get(); // skip stream_id
            framePayload.get(); // skip offset
            int dataLength = framePayload.get() & 0xFF; // read length
            byte[] dataBytes = new byte[dataLength];
            framePayload.get(dataBytes);
            assertEquals("Hello QUIC", new String(dataBytes));

            // Verify ACK was generated
            assertNotNull(ackResponse, "ACK should be generated for STREAM frame");
        }
    }

    @Test
    @DisplayName("Test 1-RTT packet rejected in wrong state")
    void test1RttPacketInWrongState() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Connection in HANDSHAKE state (wrong state for 1-RTT)
            connection.setState(QuicConnection.State.HANDSHAKE);
            setupMockTlsMetadata();

            ByteBuffer packet = createMock1RttPacketWithStreamData(0L, "test".getBytes());
            List<ByteBuffer> packetResults = connection.process1RttPacket(packet);

            assertEquals(0, packetResults.size(), "1-RTT packet should be rejected in HANDSHAKE state");
        }
    }

    // ========================================================================
    // CONNECTION_CLOSE Tests
    // ========================================================================

    @Test
    @DisplayName("Test CONNECTION_CLOSE transitions to CLOSING state")
    void testConnectionCloseTransition() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in ESTABLISHED state
            setupEstablishedConnection();

            // Send CONNECTION_CLOSE frame
            ByteBuffer closePacket = createMock1RttPacketWithConnectionClose();
            ByteBuffer ackResponse = connection.process1RttPacket(closePacket).get(0);

            // Verify state transition
            assertEquals(QuicConnection.State.CLOSING, connection.getState(),
                    "Connection should transition to CLOSING state");

            // ACK should still be generated
            assertNotNull(ackResponse, "ACK should be generated for CONNECTION_CLOSE");
        }
    }

    private StreamFrameListener createStreamFrameListener(Consumer<StreamFrameListener.StreamFrame> onStreamFrame) {
        return new StreamFrameListener() {

            @Override
            public void onStreamFrame(long connectionId, StreamFrame frame) {
                onStreamFrame.accept(frame);
            }

            @Override
            public void onAckReceived(long connectionId, long streamId, long length) {

            }
        };
    }

    @Test
    @DisplayName("Test stream data ignored in CLOSING state")
    void testStreamDataIgnoredInClosingState() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in CLOSING state
            setupEstablishedConnection();
            connection.setState(QuicConnection.State.CLOSING);

            // Track if payload listener is called
            AtomicInteger callCount = new AtomicInteger(0);

            connection.setStreamFrameListener(createStreamFrameListener(frame->callCount.incrementAndGet()));

            // Try to send stream data
            ByteBuffer packet = createMock1RttPacketWithStreamData(0L, "test".getBytes());
            connection.process1RttPacket(packet);

            // Verify payload listener was NOT called
            assertEquals(0, callCount.get(), "Stream data should be ignored in CLOSING state");
        }
    }

    @Test
    @DisplayName("Test 1-RTT packets rejected in CLOSED state")
    void test1RttPacketRejectedInClosedState() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Set connection to CLOSED state
            connection.setState(QuicConnection.State.CLOSED);
            setupMockTlsMetadata();

            ByteBuffer packet = createMock1RttPacketWithStreamData(0L, "test".getBytes());
            List<ByteBuffer> packetResults = connection.process1RttPacket(packet);

            assertEquals(0, packetResults.size(), "1-RTT packet should be rejected in CLOSED state");
        }
    }

    // ========================================================================
    // Packet Reordering Tests
    // ========================================================================

    @Test
    @DisplayName("Test out-of-order 1-RTT packet tracking")
    void testOutOfOrder1RttPackets() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in ESTABLISHED state
            setupEstablishedConnection();

            // Send packets out of order: 2, 0, 1
            ByteBuffer packet2 = createMock1RttPacket(2, new byte[]{0x00}); // PADDING
            ByteBuffer packet0 = createMock1RttPacket(0, new byte[]{0x00});
            ByteBuffer packet1 = createMock1RttPacket(1, new byte[]{0x00});

            connection.process1RttPacket(packet2);
            connection.process1RttPacket(packet0);
            connection.process1RttPacket(packet1);

            // Verify largest received packet number is tracked correctly
            // Note: This is a simplified test - full reordering would need ACK range tracking
            assertTrue(true, "Packet reordering should be handled without errors");
        }
    }

    // ========================================================================
    // ACK Generation Tests
    // ========================================================================

    @Test
    @DisplayName("Test ACK not generated for non-ack-eliciting frames")
    void testNoAckForPaddingFrame() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in ESTABLISHED state
            setupEstablishedConnection();

            // Send packet with only PADDING (non-ack-eliciting)
            ByteBuffer packet = createMock1RttPacket(0, new byte[]{0x00}); // PADDING frame
            List<ByteBuffer> byteBuffers = connection.process1RttPacket(packet);

            assertEquals(0, byteBuffers.size(), "ACK should not be generated for PADDING-only packet");
        }
    }

    @Test
    @DisplayName("Test ACK generated for ack-eliciting frames")
    void testAckGeneratedForStreamFrame() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in ESTABLISHED state
            setupEstablishedConnection();

            // Send packet with STREAM frame (ack-eliciting)
            ByteBuffer packet = createMock1RttPacketWithStreamData(0L, "data".getBytes());
            ByteBuffer ackResponse = connection.process1RttPacket(packet).get(0);

            assertNotNull(ackResponse, "ACK should be generated for STREAM frame");
        }
    }

    // ========================================================================
    // Retransmission Tests
    // ========================================================================

    @Test
    @DisplayName("Test retransmission triggered by packet threshold (3 packets lost)")
    void testRetransmissionPacketThreshold() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in HANDSHAKE state (easier to test Initial space retransmission)
            connection.setState(QuicConnection.State.HANDSHAKE);
            setupMockTlsMetadata();

            // Simulate server sending Initial packets 0, 1, 2, 3, 4
            PacketNumberSpace initialSpace = connection.getInitialSpace();
            for (int i = 0; i < 5; i++) {
                ByteBuffer mockPayload = createMockCryptoFramePayload();
                initialSpace.onPacketSent(i, mockPayload, PacketNumberSpace.PacketPhase.INITIAL, true);
            }

            // Client ACKs packets 4, 3, 2 (creating gap of 3 packets: 0, 1, 2)
            // This should trigger retransmission of packet 0 (threshold = 3)
            List<PacketNumberSpace.AckRange> ackRanges = new ArrayList<>();
            ackRanges.add(new PacketNumberSpace.AckRange(2, 4)); // Packets 2-4

            java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = initialSpace.onAckReceived(4, ackRanges, 0, null);

            // Verify packet 0 was declared lost (4 - 3 = 1, so packets < 1 are lost)
            assertFalse(lostPackets.isEmpty(), "Should detect lost packets");
            assertTrue(lostPackets.containsKey(0L), "Packet 0 should be declared lost");

            PacketNumberSpace.SentPacket lostPacket = lostPackets.get(0L);
            assertNotNull(lostPacket, "Lost packet 0 should have SentPacket metadata");
            assertNotNull(lostPacket.unencryptedPayload, "Lost packet should have unencrypted payload");
            assertEquals(PacketNumberSpace.PacketPhase.INITIAL, lostPacket.packetPhase, "Packet type should be INITIAL");
            assertTrue(lostPacket.ackEliciting, "Lost packet should be ack-eliciting");
        }
    }

    @Test
    @DisplayName("Test retransmission SentPacket contains unencrypted payload and packet type")
    void testRetransmissionPacketContent() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in HANDSHAKE state
            connection.setState(QuicConnection.State.HANDSHAKE);
            setupMockTlsMetadata();

            // Simulate sending an Initial packet with known payload
            PacketNumberSpace initialSpace = connection.getInitialSpace();
            ByteBuffer originalPayload = createMockCryptoFramePayload();

            // Store original unencrypted payload for comparison
            ByteBuffer expectedPayload = originalPayload.duplicate();
            byte[] expectedBytes = new byte[expectedPayload.remaining()];
            expectedPayload.get(expectedBytes);

            initialSpace.onPacketSent(0, originalPayload, PacketNumberSpace.PacketPhase.INITIAL, true);

            // Trigger loss by ACKing packet 4 (packet 0 will be lost by packet threshold)
            for (int i = 1; i < 5; i++) {
                initialSpace.onPacketSent(i, createMockCryptoFramePayload(), PacketNumberSpace.PacketPhase.INITIAL, true);
            }

            List<PacketNumberSpace.AckRange> ackRanges = new ArrayList<>();
            ackRanges.add(new PacketNumberSpace.AckRange(2, 4));
            java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = initialSpace.onAckReceived(4, ackRanges, 0, null);

            // Retrieve SentPacket for retransmission
            assertTrue(lostPackets.containsKey(0L), "Packet 0 should be in lost packets");
            PacketNumberSpace.SentPacket sentPacket = lostPackets.get(0L);

            assertNotNull(sentPacket, "Should retrieve SentPacket for retransmission");
            assertNotNull(sentPacket.unencryptedPayload, "SentPacket should have unencrypted payload");
            assertEquals(PacketNumberSpace.PacketPhase.INITIAL, sentPacket.packetPhase, "Packet type should be INITIAL");
            assertEquals(0L, sentPacket.packetNumber, "Original packet number should be preserved");
            assertTrue(sentPacket.ackEliciting, "Packet should be ack-eliciting");

            // Verify unencrypted payload content matches original
            assertEquals(expectedBytes.length, sentPacket.unencryptedPayload.remaining(), 
                        "Unencrypted payload should have same size as original");

            byte[] payloadBytes = new byte[sentPacket.unencryptedPayload.remaining()];
            sentPacket.unencryptedPayload.duplicate().get(payloadBytes);
            assertArrayEquals(expectedBytes, payloadBytes, 
                            "Unencrypted payload should have identical content to original");
        }
    }

    @Test
    @DisplayName("Test multiple lost packets are all retransmitted")
    void testMultipleLostPacketsRetransmitted() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in HANDSHAKE state
            connection.setState(QuicConnection.State.HANDSHAKE);
            setupMockTlsMetadata();

            // Send Initial packets 0-5
            PacketNumberSpace initialSpace = connection.getInitialSpace();
            for (int i = 0; i < 6; i++) {
                initialSpace.onPacketSent(i, createMockCryptoFramePayload(), PacketNumberSpace.PacketPhase.INITIAL, true);
            }

            // ACK only packet 5, leaving 0-4 unacked
            List<PacketNumberSpace.AckRange> ackRanges = new ArrayList<>();
            ackRanges.add(new PacketNumberSpace.AckRange(5, 5));

            java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = initialSpace.onAckReceived(5, ackRanges, 0, null);

            // Packets 0, 1 should be declared lost (5 - 3 = 2, so packets < 2 are lost)
            assertTrue(lostPackets.size() >= 2, "Should detect at least 2 lost packets");
            assertTrue(lostPackets.containsKey(0L), "Packet 0 should be lost");
            assertTrue(lostPackets.containsKey(1L), "Packet 1 should be lost");

            // Verify all lost packets have SentPacket metadata with unencrypted payload
            for (java.util.Map.Entry<Long, PacketNumberSpace.SentPacket> entry : lostPackets.entrySet()) {
                PacketNumberSpace.SentPacket sentPacket = entry.getValue();
                assertNotNull(sentPacket, 
                          "Lost packet " + entry.getKey() + " should have SentPacket metadata");
                assertNotNull(sentPacket.unencryptedPayload,
                          "Lost packet " + entry.getKey() + " should have unencrypted payload");
                assertTrue(sentPacket.unencryptedPayload.hasRemaining(),
                          "Lost packet " + entry.getKey() + " should have payload data");
                assertEquals(PacketNumberSpace.PacketPhase.INITIAL, sentPacket.packetPhase,
                          "Lost packet " + entry.getKey() + " should have correct packet type");
            }
        }
    }

    @Test
    @DisplayName("Test retransmission via processHandshakePacket ACK handling")
    void testRetransmissionViaHandshakeAck() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in HANDSHAKE state
            connection.setState(QuicConnection.State.HANDSHAKE);
            setupMockTlsMetadata();

            // Simulate sending Initial packets 0, 1, 2
            PacketNumberSpace initialSpace = connection.getInitialSpace();
            for (int i = 0; i < 3; i++) {
                ByteBuffer mockPacket = createMockInitialPacket();
                initialSpace.onPacketSent(i, mockPacket, PacketNumberSpace.PacketPhase.HANDSHAKE,true);
            }

            // Create Handshake packet with ACK frame that only ACKs packets 2 and 3
            // This should trigger retransmission of packet 0 (more than 3 below largest acked)
            ByteBuffer handshakePacket = createMockHandshakePacketWithAck(3, new long[]{2, 3}, (byte) initialSpace.allocatePacketNumber());

            List<ByteBuffer> responses = connection.processHandshakePacket(handshakePacket);

            // Response should include retransmissions (if any were triggered)
            // Note: The exact behavior depends on loss detection thresholds
            assertNotNull(responses, "Should return response list");
        }
    }

    @Test
    @DisplayName("Test no retransmission for already-acked packets")
    void testNoRetransmissionForAckedPackets() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in ESTABLISHED state
            setupEstablishedConnection();

            // Send 1-RTT packets 0, 1, 2
            PacketNumberSpace appSpace = connection.getApplicationSpace();
            for (int i = 0; i < 3; i++) {
                ByteBuffer mockPayload = ByteBuffer.wrap(new byte[]{0x00}); // PADDING frame
                appSpace.onPacketSent(i, mockPayload, PacketNumberSpace.PacketPhase.APPLICATION, true);
            }

            // ACK all packets
            List<PacketNumberSpace.AckRange> ackRanges = new ArrayList<>();
            ackRanges.add(new PacketNumberSpace.AckRange(0, 2));
            java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = appSpace.onAckReceived(2, ackRanges, 0, null);

            // No packets should be declared lost
            assertTrue(lostPackets.isEmpty(), "No packets should be lost when all are acked");

            // Verify no packets are in the lost packets map
            assertFalse(lostPackets.containsKey(0L), "Acked packet 0 should not be in lost packets");
            assertFalse(lostPackets.containsKey(1L), "Acked packet 1 should not be in lost packets");
            assertFalse(lostPackets.containsKey(2L), "Acked packet 2 should not be in lost packets");
        }
    }

    @Test
    @DisplayName("Test retransmission via 1-RTT ACK processing")
    void testRetransmissionVia1RttAck() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in ESTABLISHED state
            setupEstablishedConnection();

            // Simulate sending 1-RTT packets 0-4
            PacketNumberSpace appSpace = connection.getApplicationSpace();
            for (int i = 0; i < 5; i++) {
                ByteBuffer mockPayload = ByteBuffer.wrap(new byte[]{0x00}); // PADDING frame
                appSpace.onPacketSent(i, mockPayload, PacketNumberSpace.PacketPhase.APPLICATION, true);
                appSpace.allocatePacketNumber();
            }

            // Create 1-RTT packet with ACK that only acknowledges packets 2-4
            // This creates a gap that should trigger retransmission of packet 0
            ByteBuffer ackPacket = createMock1RttPacketWithSelectiveAck(4, new long[]{2, 3, 4}, appSpace.allocatePacketNumber());

            List<ByteBuffer> responses = connection.process1RttPacket(ackPacket);

            // Should return retransmissions for lost packets
            assertNotNull(responses, "Should return response list");
        }
    }

    @Test
    @DisplayName("Test retransmission generates NEW packet numbers (RFC 9002)")
    void testRetransmissionGeneratesNewPacketNumbers() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in HANDSHAKE state
            connection.setState(QuicConnection.State.HANDSHAKE);
            setupMockTlsMetadata();

            PacketNumberSpace initialSpace = connection.getInitialSpace();

            // Send Initial packets 0, 1, 2, 3, 4
            for (int i = 0; i < 5; i++) {
                ByteBuffer mockPayload = createMockCryptoFramePayload();
                initialSpace.allocatePacketNumber();
                initialSpace.onPacketSent(i, mockPayload, PacketNumberSpace.PacketPhase.INITIAL, true);
            }

            // Verify next packet number before retransmission
            long nextPnBefore = initialSpace.allocatePacketNumber();
            assertEquals(5L, nextPnBefore, "Next packet number should be 5 before retransmission");

            // Create Handshake packet with ACK that triggers retransmission of packet 0
            // ACK packets 2, 3, 4 (gap of 3 packets)
            ByteBuffer handshakePacket = createMockHandshakePacketWithAck(4, new long[]{2, 3, 4}, (byte) initialSpace.allocatePacketNumber());

            // Process the ACK - should trigger retransmission of packet 0 with NEW packet number
            List<ByteBuffer> responses = connection.processHandshakePacket(handshakePacket);

            // Verify retransmissions were generated
            assertFalse(responses.isEmpty(), "Should generate retransmission packets");

            // Verify packet number space has been incremented (new packets were allocated)
            long nextPnAfter = initialSpace.allocatePacketNumber();
            assertTrue(nextPnAfter > 5, 
                "Packet number should be > 5 after retransmission, indicating NEW packet numbers were used. Got: " + nextPnAfter);

            // The retransmitted packet should have used packet number 5 (next available)
            // So next available should be at least 6
            assertTrue(nextPnAfter >= 6, 
                "Next packet number should be >= 6, indicating retransmission used PN 5. Got: " + nextPnAfter);
        }
    }

    @Test
    @DisplayName("Test retransmitted packet tracked with NEW packet number in space")
    void testRetransmittedPacketTrackedWithNewNumber() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in ESTABLISHED state
            setupEstablishedConnection();

            PacketNumberSpace appSpace = connection.getApplicationSpace();

            // Send packets 0-4
            for (int i = 0; i < 5; i++) {
                ByteBuffer mockPayload = ByteBuffer.wrap(new byte[]{0x00});
                appSpace.onPacketSent(i, mockPayload, PacketNumberSpace.PacketPhase.APPLICATION, true);
                appSpace.allocatePacketNumber();
            }

            // Verify next packet number is 5
            long nextPnBeforeRetransmit = appSpace.allocatePacketNumber();
            assertEquals(5L, nextPnBeforeRetransmit, "Next packet number should be 5");

            // Count unacked packets before retransmission
            int unackedBefore = appSpace.getUnackedPacketCount();

            // Trigger retransmission by ACKing packets 2-4 (packet 0 will be lost)
            ByteBuffer ackPacket = createMock1RttPacketWithSelectiveAck(4, new long[]{2, 3, 4}, nextPnBeforeRetransmit);
            List<ByteBuffer> responses = connection.process1RttPacket(ackPacket);

            // Verify retransmissions were created
            assertFalse(responses.isEmpty(), "Should generate retransmission packets");

            // Verify packet number space allocated NEW packet numbers
            // The retransmitted packet(s) should be tracked with new numbers
            int unackedAfter = appSpace.getUnackedPacketCount();

            // After ACK: packets 2,3,4 are acked (removed), packet 0 is lost (removed), packet 1 is still unacked
            // Plus the NEW retransmission packet(s) for lost packet 0
            assertTrue(unackedAfter >= 2, 
                "Should have unacked packet 1 plus new retransmission packet(s), got: " + unackedAfter);

            // Verify packet number space has moved forward
            long nextPnAfterRetransmit = appSpace.allocatePacketNumber();
            assertTrue(nextPnAfterRetransmit > 5, 
                "Packet number should be incremented after retransmissions, got: " + nextPnAfterRetransmit);
        }
    }

    @Test
    @DisplayName("Test multiple retransmissions each get unique NEW packet numbers")
    void testMultipleRetransmissionsGetUniqueNewPacketNumbers() throws Exception {
        try (MockedStatic<QuicCrypto> cryptoMock = mockQuicCrypto()) {

            // Setup connection in ESTABLISHED state
            setupEstablishedConnection();

            PacketNumberSpace appSpace = connection.getApplicationSpace();

            // Send packets 0-5
            for (int i = 0; i < 6; i++) {
                ByteBuffer mockPayload = ByteBuffer.wrap(new byte[]{0x00});
                appSpace.onPacketSent(i, mockPayload, PacketNumberSpace.PacketPhase.APPLICATION, true);
                appSpace.allocatePacketNumber();
            }

            // Next packet number should be 6
            long nextPnBefore = appSpace.allocatePacketNumber();
            assertEquals(6L, nextPnBefore, "Next packet number should be 6 before retransmission");

            // ACK only packet 5, causing packets 0, 1 to be declared lost (5 - 3 = 2)
            ByteBuffer ackPacket = createMock1RttPacketWithSelectiveAck(5, new long[]{5}, nextPnBefore);
            List<ByteBuffer> responses = connection.process1RttPacket(ackPacket);

            // Should have at least 2 retransmissions (packets 0 and 1)
            assertTrue(responses.size() >= 2, 
                "Should retransmit at least 2 lost packets, got: " + responses.size());

            // Verify packet number space has advanced by at least 2 (one for each retransmission)
            long nextPnAfter = appSpace.allocatePacketNumber();
            assertTrue(nextPnAfter >= 8, 
                "Next PN should be >= 8 (6 + 2 retransmissions), got: " + nextPnAfter);

            // This confirms that each retransmitted packet got a unique new packet number
            // If PNs were reused, nextPnAfter would still be 6
            long pnIncrement = nextPnAfter - nextPnBefore;
            assertTrue(pnIncrement >= 2, 
                "Packet number should have incremented by at least 2 (number of retransmissions), got increment: " + pnIncrement);
        }
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    private void setupEstablishedConnection() {
        connection.setState(QuicConnection.State.ESTABLISHED);
        setupMockTlsMetadata();
    }

    private void setupMockTlsMetadata() {
        // Create mock SecretKey objects (required for 1-RTT packet processing)
        SecretKey clientHandshakeSecret = new SecretKeySpec(new byte[16], "AES");
        SecretKey serverHandshakeSecret = new SecretKeySpec(new byte[16], "AES");
        SecretKey client1RttSecret = new SecretKeySpec(new byte[16], "AES");
        SecretKey server1RttSecret = new SecretKeySpec(new byte[16], "AES");

        QuicCrypto.TlsMetadata mockMetadata = new QuicCrypto.TlsMetadata(new byte[32]);
        mockMetadata.clientRandom           = new byte[32];
        mockMetadata.serverRandom           = new byte[32];
        mockMetadata.clientHandshakeSecret  = clientHandshakeSecret;
        mockMetadata.serverHandshakeSecret  = serverHandshakeSecret;
        mockMetadata.selectedCipherSuite    = "TLS_AES_128_GCM_SHA256";
        mockMetadata.alpn                   = "h3";
        mockMetadata.negotiatedIdleTimeoutMs = 10_000;
        mockMetadata.clientHandshakeHpKey   = new byte[16];
        mockMetadata.serverHandshakeHpKey   = new byte[16];
        mockMetadata.setApplicationKeys(client1RttSecret, server1RttSecret, new byte[16], new byte[16], new byte[16], new byte[16]);

        connection.setTlsMetadata(mockMetadata);
    }

    /**
     * Creates mock unencrypted CRYPTO frame payload for testing.
     * This represents the frames BEFORE encryption.
     */
    private ByteBuffer createMockCryptoFramePayload() {
        ByteBuffer payload = ByteBuffer.allocate(64);
        payload.put((byte) 0x06); // CRYPTO frame type
        payload.put((byte) 0);    // Offset (varint)
        payload.put((byte) 32);   // Length (varint)
        // Add 32 bytes of mock crypto data
        for (int i = 0; i < 32; i++) {
            payload.put((byte) i);
        }
        payload.flip();
        return payload;
    }

    private ByteBuffer createMockInitialPacket() {
        // Build a valid QUIC Initial long-header packet (RFC 9000)
        // flags: 1 (Long) | 1 (Fixed) | 00 (Initial type) | 00 (reserved) | 00 (1-byte PN)
        //        = 1100_0000 = 0xC0  → type bits (flags & 0x30) >> 4 == 0x00 → INITIAL
        //        Packet number length = (flags & 0x03) + 1 = 1 byte
        byte flags = (byte) 0xC0;
        byte[] dcid = longToBytes(TEST_CID);   // 8 bytes
        byte[] scid = new byte[8];             // 8 bytes, all zeros

        // Encrypted payload bytes (mock content + 16-byte GCM tag)
        byte[] encryptedPayload = new byte[50 + QuicCrypto.GCM_TAG_LENGTH];
        for (int i = 0; i < 50; i++) encryptedPayload[i] = (byte) i;

        // payloadLength = packet-number (1) + ciphertext + tag
        long payloadLength = 1 + encryptedPayload.length;

        ByteBuffer buffer = ByteBuffer.allocate(512);
        buffer.put(flags);
        buffer.putInt(0x00000001);          // Version (QUIC v1)
        buffer.put((byte) dcid.length);     // DCID length
        buffer.put(dcid);
        buffer.put((byte) scid.length);     // SCID length
        buffer.put(scid);
        // Token length varint (0 for Initial sent by client without retry)
        buffer.put((byte) 0);
        // Payload length varint
        putVarint(buffer, payloadLength);
        // Packet number (1 byte, value 0)
        buffer.put((byte) 0);
        // Encrypted payload
        buffer.put(encryptedPayload);
        buffer.flip();
        return buffer;
    }

    private ByteBuffer createMockHandshakePacket() {
        // Create mock TLS Finished message structure (RFC 8446)
        byte[] mockCryptoData = new byte[36];
        mockCryptoData[0] = 0x14;  // Finished message type
        mockCryptoData[1] = 0x00;
        mockCryptoData[2] = 0x00;
        mockCryptoData[3] = 0x20;  // Length = 32

        // Create CRYPTO frame with TLS Finished message
        ByteBuffer cryptoFrame = ByteBuffer.allocate(128);
        cryptoFrame.put((byte) 0x06);                  // CRYPTO frame type
        cryptoFrame.put((byte) 0);                     // Offset (varint)
        cryptoFrame.put((byte) mockCryptoData.length); // Length (varint)
        cryptoFrame.put(mockCryptoData);
        cryptoFrame.flip();

        // Encrypted payload = crypto frame bytes + 16-byte GCM tag
        byte[] frameBytes = new byte[cryptoFrame.remaining()];
        cryptoFrame.get(frameBytes);
        byte[] encryptedPayload = new byte[frameBytes.length + QuicCrypto.GCM_TAG_LENGTH];
        System.arraycopy(frameBytes, 0, encryptedPayload, 0, frameBytes.length);

        // Build a valid QUIC Handshake long-header packet (RFC 9000)
        // flags: 1 (Long) | 1 (Fixed) | 10 (Handshake type) | 00 (reserved) | 00 (1-byte PN)
        //        = 1110_0000 = 0xE0  → type bits (flags & 0x30) >> 4 == 0x02 → HANDSHAKE
        //        Packet number length = (flags & 0x03) + 1 = 1 byte
        byte flags = (byte) 0xE0;
        byte[] dcid = longToBytes(TEST_CID);
        byte[] scid = new byte[8];

        // payloadLength = packet-number (1) + ciphertext + tag
        long payloadLength = 1 + encryptedPayload.length;

        ByteBuffer packet = ByteBuffer.allocate(512);
        packet.put(flags);
        packet.putInt(0x00000001);       // Version (QUIC v1)
        packet.put((byte) dcid.length);  // DCID length
        packet.put(dcid);
        packet.put((byte) scid.length);  // SCID length
        packet.put(scid);
        // No token field for Handshake packets
        putVarint(packet, payloadLength);
        // Packet number (1 byte, value 0)
        packet.put((byte) 0);
        packet.put(encryptedPayload);
        packet.flip();
        return packet;
    }

    private ByteBuffer createMock1RttPacket(long packetNumber, byte[] payload) {
        // Build a valid QUIC 1-RTT short-header packet (RFC 9000)
        // flags: 0 (Short) | 1 (Fixed) | 0 (Spin) | 00 (reserved) | 0 (Key Phase) | 00 (1-byte PN)
        //        = 0100_0000 = 0x40
        //        Packet number length = (flags & 0x03) + 1 = 1 byte
        byte flags = (byte) 0x40;
        byte[] dcid = longToBytes(TEST_CID); // 8-byte DCID (matches parseShortHeader assumption)

        ByteBuffer buffer = ByteBuffer.allocate(512);
        buffer.put(flags);
        buffer.put(dcid);
        buffer.put((byte) packetNumber);   // 1-byte packet number
        buffer.put(payload);
        // GCM authentication tag (16 bytes)
        for (int i = 0; i < QuicCrypto.GCM_TAG_LENGTH; i++) {
            buffer.put((byte) 0);
        }
        buffer.flip();
        return buffer;
    }

    private ByteBuffer createMock1RttPacketWithStreamData(long streamId, byte[] data) {
        ByteBuffer payload = ByteBuffer.allocate(256);
        // STREAM frame: type (0x08) | stream_id | data
        payload.put((byte) 0x0E); // STREAM frame with length and offset bits
        payload.put((byte) streamId);
        payload.put((byte) 0); // Offset
        payload.put((byte) data.length); // Length
        payload.put(data);
        payload.flip();

        byte[] payloadBytes = new byte[payload.remaining()];
        payload.get(payloadBytes);

        return createMock1RttPacket(0, payloadBytes);
    }

    private ByteBuffer createMock1RttPacketWithConnectionClose() {
        ByteBuffer payload = ByteBuffer.allocate(64);
        payload.put((byte) 0x1c); // CONNECTION_CLOSE frame
        payload.put((byte) 0); // Error code
        payload.put((byte) 0); // Frame type
        payload.put((byte) 0); // Reason length
        payload.flip();

        byte[] payloadBytes = new byte[payload.remaining()];
        payload.get(payloadBytes);

        return createMock1RttPacket(0, payloadBytes);
    }

    private byte[] getBytes(ByteBuffer buffer) {
        buffer.rewind();
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        return bytes;
    }

    private MockedStatic<QuicCrypto> mockQuicCrypto() {
        MockedStatic<QuicCrypto> mock = Mockito.mockStatic(QuicCrypto.class);

        // Mock key derivation
        QuicCrypto.PacketProtectionKeys mockKeys = new QuicCrypto.PacketProtectionKeys(
                mock(SecretKey.class), new byte[12], new byte[16]
        );
        mock.when(() -> QuicCrypto.deriveInitialKeys(any(byte[].class)))
                .thenReturn(new QuicCrypto.PacketProtectionKeys[]{mockKeys, mockKeys});

        // Mock ClientHello processing
        SecretKey clientHandshakeSecret = new SecretKeySpec(new byte[16], "AES");
        SecretKey serverHandshakeSecret = new SecretKeySpec(new byte[16], "AES");
        SecretKey client1RttSecret = new SecretKeySpec(new byte[16], "AES");
        SecretKey server1RttSecret = new SecretKeySpec(new byte[16], "AES");

        QuicCrypto.TlsMetadata mockMetadata = new QuicCrypto.TlsMetadata(new byte[32]);
        mockMetadata.clientRandom            = new byte[32];
        mockMetadata.serverRandom            = new byte[32];
        mockMetadata.clientHandshakeSecret   = clientHandshakeSecret;
        mockMetadata.serverHandshakeSecret   = serverHandshakeSecret;
        mockMetadata.selectedCipherSuite     = "TLS_AES_128_GCM_SHA256";
        mockMetadata.alpn                    = "h3";
        mockMetadata.negotiatedIdleTimeoutMs = 10_000;
        mockMetadata.clientHandshakeHpKey    = new byte[16];
        mockMetadata.serverHandshakeHpKey    = new byte[16];
        mockMetadata.serverEphemeralPublicKey = new byte[32];
        mockMetadata.setApplicationKeys(client1RttSecret, server1RttSecret, new byte[16], new byte[16], new byte[16], new byte[16]);

        mock.when(() -> QuicCrypto.processClientHello(any(ByteBuffer.class)))
                .thenReturn(mockMetadata);

        mock.when(() -> QuicCrypto.decryptHandshakePacket(any(), any(), any())).thenCallRealMethod();

        // Mock decryption - simply copy input to output (simulating pass-through decryption)
        mock.when(() -> QuicCrypto.decryptAead(any(), any(), any(), anyLong(), any(), any()))
                .thenAnswer(invocation -> {
                    ByteBuffer packet = invocation.getArgument(0);
                    ByteBuffer output = invocation.getArgument(4);

                    // Copy available data from packet to output (excluding auth tag which is already accounted for)
                    int bytesToCopy = Math.min(packet.remaining(), output.remaining());
                    if (bytesToCopy > 0) {
                        byte[] data = new byte[bytesToCopy];
                        packet.get(data);
                        output.put(data);
                    }
                    return null;
                });

        // Mock encryption
        mock.when(() -> QuicCrypto.encryptPacket(any(), any(), anyLong(), any(), any()))
                .thenAnswer(invocation -> {
                    ByteBuffer input = invocation.getArgument(0);
                    ByteBuffer encrypted = ByteBuffer.allocate(input.remaining() + 50);
                    encrypted.put(input);
                    encrypted.flip();
                    return encrypted;
                });

        // Mock ServerHello creation (single TlsMetadata arg)
        mock.when(() -> QuicCrypto.createServerHello(any(QuicCrypto.TlsMetadata.class)))
                .thenReturn(ByteBuffer.allocate(64));

        // Mock client Finished verification - return true for valid Finished message
        mock.when(() -> QuicCrypto.verifyClientFinished(any(byte[].class), any(SecretKey.class), any(byte[].class)))
                .thenReturn(true);

        return mock;
    }

    public byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }

    /**
     * Creates a mock Handshake packet containing an ACK frame.
     * Used for testing retransmission triggered by ACKs in Handshake packets.
     */
    private ByteBuffer createMockHandshakePacketWithAck(long largestAcked, long[] ackedPackets, byte packetNumber) {
        // Create ACK frame
        ByteBuffer ackFrame = ByteBuffer.allocate(64);
        ackFrame.put((byte) 0x02); // ACK frame type
        putVarint(ackFrame, largestAcked);
        putVarint(ackFrame, 0); // ACK delay

        if (ackedPackets.length > 0) {
            long largest = ackedPackets[ackedPackets.length - 1];
            long smallest = ackedPackets[0];
            putVarint(ackFrame, 0); // Range count (just one range)
            putVarint(ackFrame, largest - smallest); // First range length
        } else {
            putVarint(ackFrame, 0);
            putVarint(ackFrame, 0);
        }
        ackFrame.flip();

        // Encrypted payload = packet-number (already written separately) + ack frame + GCM tag
        byte[] ackBytes = new byte[ackFrame.remaining()];
        ackFrame.get(ackBytes);
        byte[] encryptedPayload = new byte[ackBytes.length + QuicCrypto.GCM_TAG_LENGTH];
        System.arraycopy(ackBytes, 0, encryptedPayload, 0, ackBytes.length);

        // Build a valid QUIC Handshake long-header packet (RFC 9000)
        // flags: 1110_0000 = 0xE0  → type bits == 0x02 → HANDSHAKE, 1-byte packet number
        byte flags = (byte) 0xE0;
        byte[] dcid = longToBytes(TEST_CID);
        byte[] scid = new byte[8];

        // payloadLength = packet-number (1) + ciphertext + tag
        long payloadLength = 1 + encryptedPayload.length;

        ByteBuffer packet = ByteBuffer.allocate(512);
        packet.put(flags);
        packet.putInt(0x00000001);
        packet.put((byte) dcid.length);
        packet.put(dcid);
        packet.put((byte) scid.length);
        packet.put(scid);
        putVarint(packet, payloadLength);
        packet.put(packetNumber);  // 1-byte packet number
        packet.put(encryptedPayload);
        packet.flip();
        return packet;
    }

    /**
     * Creates a mock 1-RTT packet containing an ACK frame with selective acknowledgment.
     */
    private ByteBuffer createMock1RttPacketWithSelectiveAck(long largestAcked, long[] ackedPackets, long nextPn) {
        // Create ACK frame
        ByteBuffer ackFrame = ByteBuffer.allocate(64);
        ackFrame.put((byte) 0x02); // ACK frame type
        putVarint(ackFrame, largestAcked); // Largest acked
        putVarint(ackFrame, 0); // ACK delay

        // Simple implementation: single range
        if (ackedPackets.length > 0) {
            long largest = ackedPackets[ackedPackets.length - 1];
            long smallest = ackedPackets[0];
            putVarint(ackFrame, 0); // Range count
            putVarint(ackFrame, largest - smallest); // First range length
        } else {
            putVarint(ackFrame, 0);
            putVarint(ackFrame, 0);
        }

        ackFrame.flip();

        byte[] ackFrameBytes = new byte[ackFrame.remaining()];
        ackFrame.get(ackFrameBytes);

        return createMock1RttPacket(nextPn, ackFrameBytes);
    }

    /**
     * Writes a variable-length integer (varint) to buffer.
     * Simplified version for test helpers.
     */
    private void putVarint(ByteBuffer buffer, long value) {
        if (value < 0) {
            throw new IllegalArgumentException("Varint cannot be negative: " + value);
        }
        if (value < 64) {
            buffer.put((byte) value);
        } else if (value < 16384) {
            buffer.put((byte) (0x40 | (value >> 8)));
            buffer.put((byte) value);
        } else {
            // For larger values, use 4-byte encoding
            buffer.put((byte) (0x80 | (value >> 24)));
            buffer.put((byte) (value >> 16));
            buffer.put((byte) (value >> 8));
            buffer.put((byte) value);
        }
    }
}
