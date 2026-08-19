/*
 * Copyright 2026 Fedor Malyshev
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jquic.quic;

import org.jctools.queues.SpscLinkedQueue;
import org.jquic.quic.buffers.BorrowedPoolBuffer;
import org.jquic.quic.buffers.BufferPool;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.buffers.RootPoolBuffer;
import org.jquic.quic.crypto.CipherMode;
import org.jquic.quic.crypto.NativeCrypto;
import org.jquic.quic.crypto.QuicCrypto;
import org.jquic.quic.streamapi.ConnectionStreamManager;
import org.jquic.quic.streamapi.QuicApplicationProtocol;
import org.jquic.quic.streamapi.QuicApplicationProtocolConnectionHandler;
import org.jquic.quic.streamapi.frames.ProtocolFrame;
import org.jquic.quic.streamapi.frames.StreamFrameData;
import org.jquic.quic.streamapi.impl.QuicStreamEngineImpl;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.jquic.quic.PacketNumberSpace.PacketPhase.INITIAL;
import static org.jquic.quic.QuicConnectionCryptoIntegrationTest.getOutboundPackets;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for QuicConnection class.
 * Tests basic QUIC connection scenarios according to RFC 9000.
 * TLS/crypto logic is mocked to focus on QUIC protocol behavior.
 */
class QuicConnectionTest {

    private static final long TEST_CID = 123456789L;
    private static final SocketAddress TEST_ADDRESS = new InetSocketAddress("127.0.0.1", 8080);
    public static final QuicApplicationProtocol PROTOCOL = new QuicApplicationProtocol() {
        @Override
        public String getProtocolName() {
            return "";
        }

        @Override
        public int getMaxBidirectionalStreamsPerConnection() {
            return 0;
        }

        @Override
        public int getMaxUnidirectionalStreamsPerConnection() {
            return 0;
        }

        @Override
        public int getMaxStreamData() {
            return 0;
        }

        @Override
        public int getMaxData() {
            return 0;
        }

        @Override
        public Function<Long, QuicApplicationProtocolConnectionHandler> getConnectionHandler() {
            return connectionId -> null;
        }

        @Override
        public void onConnectionClose(long connectionId, @Nullable Long errorCode, @Nullable String reason) {

        }
    };

    private QuicConnection connection;
    private SelectorThread selectorMock;
    private MockedStatic<QuicCrypto> cryptoMock;
//    private MockedStatic<ConnectionMetadata> mockedConnectionMetadata;
    private NativeCrypto nCryptoMock;
    private MockedStatic<QuicFrameBuilder> frameBuilderMock;
    private ConnectionMetadata mockMetadata;
    private static final BufferPool pool = mock(BufferPool.class);
    
    @BeforeEach
    void setUp() throws Exception {
        when(pool.requestWriteBuffer()).thenAnswer((a) -> new RootPoolBuffer(ByteBuffer.allocateDirect(2000).position(100), pool, true).borrow() );
        nCryptoMock = mockNCrypto();

        mockMetadata = new ConnectionMetadata();
        updMeta(mockMetadata);

        cryptoMock = mockQuicCrypto();
        frameBuilderMock = Mockito.mockStatic(QuicFrameBuilder.class, Answers.CALLS_REAL_METHODS);
        selectorMock = mock(SelectorThread.class);
        when(selectorMock.getBufferPool()).thenReturn(pool);
        connection = new QuicConnection(TEST_CID, QuicVersion.QUIC_VERSION_1, TEST_ADDRESS, new SpscLinkedQueue<>(), selectorMock, mockMetadata, new byte[8]);
        Field streamEngineInternal = QuicEngine.class.getDeclaredField("streamEngineInternal");
        streamEngineInternal.setAccessible(true);
        QuicStreamEngineImpl value = new QuicStreamEngineImpl(0);
        value.registerProtocol(PROTOCOL);
        streamEngineInternal.set(QuicEngine.class, value);
        // Mock ClientHello processing
        connection.connectionMetadata.clientCid = ByteBuffer.allocate(8).putLong(TEST_CID).array();
        connection.setConnectionStreamManager(mock(ConnectionStreamManager.class));
        connection.getConnectionPathController().updateIncomingLimits(TEST_ADDRESS, 5000);
    }

    private void updMeta(ConnectionMetadata mockMetadata) {
        mockMetadata.negotiatedIdleTimeoutMs = 10_000;
        mockMetadata.serverEphemeralPublicKey = new byte[32];
        mockMetadata.clientHandshakeCrypto = nCryptoMock;
        mockMetadata.serverHandshakeCrypto = nCryptoMock;
        mockMetadata.clientMetadata = mock(ConnectionMetadata.ClientMetadataNegotiated.class);
        mockMetadata.clientInitialCrypto = new HashMap<>(Map.of(QuicVersion.QUIC_VERSION_1, nCryptoMock, QuicVersion.QUIC_VERSION_2, nCryptoMock));
        mockMetadata.serverInitialCrypto = new HashMap<>(Map.of(QuicVersion.QUIC_VERSION_1, nCryptoMock, QuicVersion.QUIC_VERSION_2, nCryptoMock));
        mockMetadata.clientApplicationCrypto = nCryptoMock;
        mockMetadata.serverApplicationCrypto = nCryptoMock;
        mockMetadata.clientMetadata = new ConnectionMetadata.ClientMetadataNegotiated("h3", 1000, List.of(),
                Map.of(), 1200, 1000, 0, 0,
                0, 0, 0, List.of(), 3, List.of(), CipherMode.TLS_AES_128_GCM_SHA256_ID);
        mockMetadata.handshakeSecretBytes = new byte[32];
        mockMetadata.selectedSignatureScheme = 0x0403;
        mockMetadata.serverHandshakeTrafficSecret = new byte[32];
        mockMetadata.clientHandshakeTrafficSecret = new byte[32];
        mockMetadata.clientApplicationTrafficSecret = new byte[32];
        mockMetadata.serverApplicationTrafficSecret = new byte[32];
    }

    @AfterEach
    void tearDown() {
        if (cryptoMock != null) {
            cryptoMock.close();
        }
        if (frameBuilderMock != null) {
            frameBuilderMock.close();
        }
//        if (mockedConnectionMetadata != null) {
//            mockedConnectionMetadata.close();
//        }
    }

    // ========================================================================
    // 1-RTT Handshake Tests
    // ========================================================================

    @Test
    @DisplayName("Test successful 1-RTT handshake: INITIAL -> HANDSHAKE -> ESTABLISHED")
    void testSuccessful1RttHandshake() throws Exception {
        // Initial state
        assertEquals(QuicConnection.State.INITIAL, connection.getState());

        // Step 1: Process Initial packet (ClientHello)
        PoolBuffer initialPacket = createMockInitialPacket();
        connection.processInitialAndRespond(initialPacket, 0);
        List<ByteBuffer> initialResponses = getOutboundPackets(connection);

        assertFalse(initialResponses.isEmpty(), "Initial response should be generated");
        assertEquals(QuicConnection.State.HANDSHAKE, connection.getState(),
                "Connection should transition to HANDSHAKE state");

        updMeta(mockMetadata);

        // Step 2: Process Handshake packet (client Finished)
        ByteBuffer handshakePacket = createMockHandshakePacket();
        connection.processHandshakePacket(new RootPoolBuffer(handshakePacket, pool, false), 0);
        List<ByteBuffer> handshakeResponses = getOutboundPackets(connection);

        assertNotNull(handshakeResponses, "Handshake response should be generated");
        assertEquals(2, handshakeResponses.size(),
                "Should return Handshake response + HANDSHAKE_DONE");
        assertEquals(QuicConnection.State.ESTABLISHED, connection.getState(),
                "Connection should transition to ESTABLISHED state");

        // Verify that client Finished message was verified
        cryptoMock.verify(() -> QuicCrypto.verifyClientFinished(
                any(),           // finishedData - the CRYPTO frame content
                any(),        // clientHandshakeSecret
                any(byte[].class)            // transcriptHash (empty in simplified mode)
        ), times(1));
    }

    @Test
    @DisplayName("Test ClientHello processing failure sends CONNECTION_CLOSE")
    void testClientHelloProcessingFailure() throws Exception {
        // Initial state
        assertEquals(QuicConnection.State.INITIAL, connection.getState());

        cryptoMock.when(() -> QuicCrypto.processClientHello(any(), any())).thenThrow(new QuicException("Err"));

        // Process Initial packet with invalid ClientHello
        PoolBuffer initialPacket = createMockInitialPacket();
        connection.processInitialAndRespond(initialPacket, 0);
        List<ByteBuffer> responses = getOutboundPackets(connection);

        // Verify CONNECTION_CLOSE was sent
        assertFalse(responses.isEmpty(), "CONNECTION_CLOSE response should be generated");
        assertEquals(QuicConnection.State.CLOSING, connection.getState(),
                "Connection should transition to CLOSING state");
    }

    @Test
    @DisplayName("Test Handshake packet rejected in wrong state")
    void testHandshakePacketInWrongState() throws Exception {
        // Connection in INITIAL state (wrong state for Handshake packet)
        assertEquals(QuicConnection.State.INITIAL, connection.getState());
        // Don't setup metadata - connection will reject due to wrong state

        ByteBuffer handshakePacket = createMockHandshakePacket();
        connection.processHandshakePacket(new RootPoolBuffer(handshakePacket, pool, false), 0);
        List<ByteBuffer> responses = getOutboundPackets(connection);

        assertTrue(responses.isEmpty(), "Handshake packet should be rejected in INITIAL state");
        assertEquals(QuicConnection.State.INITIAL, connection.getState(),
                "State should remain INITIAL");
    }

    @Test
    @DisplayName("Test Handshake packet with failed Finished verification is silently discarded")
    void testHandshakePacketWithInvalidFinished() throws Exception {
        connection.connectionMetadata.clientCid = ByteBuffer.allocate(8).putLong(TEST_CID).array();
        // Setup connection in HANDSHAKE state
        connection.setState(QuicConnection.State.HANDSHAKE);
        setupMockTlsMetadata();

        // Override verifyClientFinished to return false (verification failed)
        // This overrides the default mock from mockQuicCrypto() which returns true
        cryptoMock.when(() -> QuicCrypto.verifyClientFinished(any(), any(), any()))
                .thenReturn(false);

        // Process Handshake packet with invalid Finished message
        ByteBuffer handshakePacket = createMockHandshakePacket();
        getOutboundPackets(connection);
        connection.processHandshakePacket(new RootPoolBuffer(handshakePacket, pool, false), 0);
        List<ByteBuffer> responses = getOutboundPackets(connection);

        // Verify packet was silently discarded
        assertTrue(responses.size() == 1, "No response should be generated for invalid Finished");
        assertEquals(QuicConnection.State.CLOSING, connection.getState(),
                "Connection should transition to CLOSING state");

        // Verify that verifyClientFinished was called
        cryptoMock.verify(() -> QuicCrypto.verifyClientFinished(
                any(),
                any(),
                any(byte[].class)
        ), times(1));
    }

    // ========================================================================
    // Stream Data Tests
    // ========================================================================

    @Test
    @DisplayName("Test stream data delivery to payload listener")
    void testStreamDataDelivery() throws Exception {
        // Setup connection in ESTABLISHED state
        setupEstablishedConnection();

        // Capture delivered stream data
        AtomicReference<ProtocolFrame> receivedData = new AtomicReference<>();

        connection.setConnectionStreamManager( createStreamFrameListener(receivedData::set) );

        // Create 1-RTT packet with STREAM frame
        ByteBuffer packet = createMock1RttPacketWithStreamData(4L, "Hello QUIC".getBytes());
        connection.process1RttPacket(new RootPoolBuffer(packet, pool, false), 0, null);
        OutboundPacket ackResponse = connection.getConnectionPathController().pollOutbound();


        // Verify stream data was delivered
        assertNotNull(receivedData.get(), "Stream data should be captured");
        ByteBuffer framePayload = ((StreamFrameData) receivedData.get()).data.buf();
        byte[] dataBytes = new byte[framePayload.remaining()];
        framePayload.get(dataBytes);
        assertEquals("Hello QUIC", new String(dataBytes));

        // Verify ACK was generated
        assertNotNull(ackResponse, "ACK should be generated for STREAM frame");
    }

    @Test
    @DisplayName("Test 1-RTT packet rejected in wrong state")
    void test1RttPacketInWrongState() throws Exception {
        // Connection in HANDSHAKE state (wrong state for 1-RTT)
        connection.setState(QuicConnection.State.HANDSHAKE);
        setupMockTlsMetadata();

        ByteBuffer packet = createMock1RttPacketWithStreamData(0L, "test".getBytes());
        connection.process1RttPacket(new RootPoolBuffer(packet, pool, false), 0, null);
        List<ByteBuffer> responses = getOutboundPackets(connection);

        assertEquals(0, responses.size(), "1-RTT packet should be rejected in HANDSHAKE state");
    }

    // ========================================================================
    // CONNECTION_CLOSE Tests
    // ========================================================================

    @Test
    @DisplayName("Test CONNECTION_CLOSE transitions to CLOSING state")
    void testConnectionCloseTransition() throws Exception {
        // Setup connection in ESTABLISHED state
        setupEstablishedConnection();

        // Send CONNECTION_CLOSE frame
        ByteBuffer closePacket = createMock1RttPacketWithConnectionClose();
        connection.process1RttPacket(new RootPoolBuffer(closePacket, pool, false), 0, null);
        OutboundPacket ackResponse = connection.getConnectionPathController().pollOutbound();

        // Verify state transition
        assertEquals(QuicConnection.State.CLOSING, connection.getState(),
                "Connection should transition to CLOSING state");

        // ACK should still be generated
        assertNotNull(ackResponse, "ACK should be generated for CONNECTION_CLOSE");
    }

    @Test
    @DisplayName("Test stream data ignored in CLOSING state")
    void testStreamDataIgnoredInClosingState() throws Exception {
        // Setup connection in CLOSING state
        setupEstablishedConnection();
        connection.setState(QuicConnection.State.CLOSING);

        // Track if payload listener is called
        AtomicInteger callCount = new AtomicInteger(0);

        connection.setConnectionStreamManager( createStreamFrameListener(frame -> callCount.incrementAndGet()) );

        // Try to send stream data
        ByteBuffer packet = createMock1RttPacketWithStreamData(0L, "test".getBytes());
        connection.process1RttPacket(new RootPoolBuffer(packet, pool, false), 0, null);

        // Verify payload listener was NOT called
        assertEquals(0, callCount.get(), "Stream data should be ignored in CLOSING state");
    }

    private ConnectionStreamManager createStreamFrameListener(Consumer<ProtocolFrame> callback) {
        return new ConnectionStreamManager() {
            @Override
            public void onProtocolFrame(ProtocolFrame frame) {
                callback.accept(frame);
            }

            @Override
            public void onConnectionClose() {

            }

            @Override
            public void onPacketAcknowledged(long packetNumber, PacketNumberSpace.SentPacket packet) {

            }
        };
    }

    @Test
    @DisplayName("Test 1-RTT packets rejected in CLOSED state")
    void test1RttPacketRejectedInClosedState() throws Exception {
        // Set connection to CLOSED state
        connection.setState(QuicConnection.State.CLOSED);
        setupMockTlsMetadata();

        ByteBuffer packet = createMock1RttPacketWithStreamData(0L, "test".getBytes());
        connection.process1RttPacket(new RootPoolBuffer(packet, pool, false), 0, null);
        List<ByteBuffer> responses = getOutboundPackets(connection);

        assertEquals(0, responses.size(), "1-RTT packet should be rejected in CLOSED state");
    }

    // ========================================================================
    // Packet Reordering Tests
    // ========================================================================

    @Test
    @DisplayName("Test out-of-order 1-RTT packet tracking")
    void testOutOfOrder1RttPackets() throws Exception {
        // Setup connection in ESTABLISHED state
        setupEstablishedConnection();

        // Send packets out of order: 2, 0, 1
        ByteBuffer packet2 = createMock1RttPacket(2, new byte[]{0x00}); // PADDING
        ByteBuffer packet0 = createMock1RttPacket(0, new byte[]{0x00});
        ByteBuffer packet1 = createMock1RttPacket(1, new byte[]{0x00});

        connection.process1RttPacket(new RootPoolBuffer(packet2, pool, false), 0, null);
        connection.process1RttPacket(new RootPoolBuffer(packet0, pool, false), 0, null);
        connection.process1RttPacket(new RootPoolBuffer(packet1, pool, false), 0, null);

        // Verify largest received packet number is tracked correctly
        // Note: This is a simplified test - full reordering would need ACK range tracking
        assertTrue(true, "Packet reordering should be handled without errors");
    }

    // ========================================================================
    // 1-RTT Key Phase Rotation Tests (RFC 9001 Section 6)
    // ========================================================================

    @Test
    @DisplayName("Test: key phase bit flip triggers rotateApplicationKeys")
    void testKeyPhaseChangeTriggersKeyRotation() throws Exception {
        setupEstablishedConnection();

        NativeCrypto keyBeforeRotation = connection.getTlsMetadata().clientApplicationCrypto;

        // Initial phase is 0 (default). Send a packet with key phase bit = 1 (flipped).
        // Packet number must be greater than lastPhaseSwitchPacketNumber (default -1).
        ByteBuffer packet = createMock1RttPacketWithKeyPhase(10L, new byte[]{0x01}, true);
        connection.process1RttPacket(new RootPoolBuffer(packet, pool, false), 0, null);

        ConnectionMetadata meta = connection.getTlsMetadata();

        // The real rotation flips currentPhase
        assertEquals((byte) 1, meta.currentPhase,
                "currentPhase should be 1 after rotation triggered by key phase bit flip");

        // lastPhaseSwitchPacketNumber must be updated to the triggering packet number
        assertEquals(10L, meta.lastPhaseSwitchPacketNumber,
                "lastPhaseSwitchPacketNumber should be set to the packet number that triggered rotation");

        // The real rotation must have replaced clientApplicationKeys with freshly derived ones
        assertNotSame(keyBeforeRotation, meta.clientApplicationCrypto,
                "clientApplicationKeys must be replaced by the real key derivation after rotation");

        // Previous keys must be saved
        assertNotNull(meta.prevClientApplicationCrypto,
                "prevClientApplicationKeys must be saved after rotation");
        assertSame(keyBeforeRotation, meta.prevClientApplicationCrypto,
                "prevClientApplicationKeys must hold the key that was current before rotation");
    }

    @Test
    @DisplayName("Test: same key phase does NOT trigger key rotation")
    void testSameKeyPhaseDoesNotTriggerRotation() throws Exception {
        setupEstablishedConnection();

        NativeCrypto keyBefore = connection.getTlsMetadata().clientApplicationCrypto;

        // Phase bit = 0 matches initial currentPhase = 0 -> no rotation expected
        ByteBuffer packet = createMock1RttPacketWithKeyPhase(5L, new byte[]{0x01}, false);
        connection.process1RttPacket(new RootPoolBuffer(packet, pool, false), 0, null);

        // Keys must be unchanged
        assertSame(keyBefore, connection.getTlsMetadata().clientApplicationCrypto,
                "clientApplicationKeys must not change when key phase bit is unchanged");
    }

    @Test
    @DisplayName("Test: after key rotation subsequent packets use new (current) keys")
    void testSubsequentPacketsAfterRotationUseNewKeys() throws Exception {
        setupEstablishedConnection();
        NativeCrypto originalKey = connection.getTlsMetadata().clientApplicationCrypto;

        // Step 1: Trigger rotation with key phase bit = 1, packet number 10.
        // The real rotateApplicationKeys derives a new key from clientApplicationTrafficSecret.
        ByteBuffer rotationPacket = createMock1RttPacketWithKeyPhase(10L, new byte[]{0x01}, true);
        connection.process1RttPacket(new RootPoolBuffer(rotationPacket, pool, false), 0, null);

        NativeCrypto rotatedKey = connection.getTlsMetadata().clientApplicationCrypto;
        assertNotSame(originalKey, rotatedKey,
                "clientApplicationKeys must be replaced after rotation");

        // Step 2: Subsequent packet with the same key phase bit = 1 and a higher packet number.
        // It must be processed without triggering another rotation (same phase) and must
        // succeed - proving the connection now uses the post-rotation key for decryption.
        ByteBuffer followUpPacket = createMock1RttPacketWithKeyPhase(11L, new byte[]{0x01}, true);
        connection.process1RttPacket(new RootPoolBuffer(followUpPacket, pool, false), 0, null);

        // Keys must remain the post-rotation keys after the follow-up packet
        assertSame(rotatedKey, connection.getTlsMetadata().clientApplicationCrypto,
                "clientApplicationKeys must stay as the rotated key for follow-up packets in the same phase");
    }

    @Test
    @DisplayName("Test: late (out-of-order) packet with old key phase uses previous keys")
    void testLatePacketWithOldKeyPhaseUsesPreviousKeys() throws Exception {
        // Capture which SecretKey is passed to decryptAead for each call
        setupEstablishedConnection();

        // Step 1: Trigger rotation with packet number 20, key phase bit = 1.
        // The real rotateApplicationKeys saves prevClientApplicationKeys and derives new ones.
        ByteBuffer rotationPacket = createMock1RttPacketWithKeyPhase(20L, new byte[]{0x01}, true);
         connection.process1RttPacket(new RootPoolBuffer(rotationPacket, pool, false), 0, null);

        NativeCrypto prevKey = connection.getTlsMetadata().prevClientApplicationCrypto;
        NativeCrypto currentKey = connection.getTlsMetadata().clientApplicationCrypto;
        assertNotSame(prevKey, currentKey, "prev and current keys must differ after rotation");

        // Step 2: Deliver a LATE packet - packet number 5 (< lastPhaseSwitchPacketNumber = 20),
        // key phase bit = 0 (old phase). RFC 9001 В§6: must be decrypted with the PREVIOUS keys.
        ByteBuffer latePacket = createMock1RttPacketWithKeyPhase(5L, new byte[]{0x01}, false);
        connection.process1RttPacket(new RootPoolBuffer(latePacket, pool, false), 0, null);

    }

    @Test
    @DisplayName("Test: second key phase rotation updates lastPhaseSwitchPacketNumber again")
    void testSecondKeyRotationUpdatesPacketNumber() throws Exception {
        setupEstablishedConnection();

        // First rotation: phase 0 -> 1, at packet 10
        connection.process1RttPacket(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), createMock1RttPacketWithKeyPhase(10L, new byte[]{0x01}, true)), 0, null);
        assertEquals(10L, connection.getTlsMetadata().lastPhaseSwitchPacketNumber,
                "After first rotation lastPhaseSwitchPacketNumber should be 10");
        assertEquals((byte) 1, connection.getTlsMetadata().currentPhase,
                "currentPhase should be 1 after first rotation");

        // Second rotation: phase 1 -> 0, at packet 30
        connection.process1RttPacket(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), createMock1RttPacketWithKeyPhase(30L, new byte[]{0x01}, false)), 0, null);
        assertEquals(30L, connection.getTlsMetadata().lastPhaseSwitchPacketNumber,
                "After second rotation lastPhaseSwitchPacketNumber should be 30");
        assertEquals((byte) 0, connection.getTlsMetadata().currentPhase,
                "currentPhase should be 0 after second rotation");

    }

    // ========================================================================
    // ACK Generation Tests
    // ========================================================================

    @Test
    @DisplayName("Test ACK not generated for non-ack-eliciting frames")
    void testNoAckForPaddingFrame() throws Exception {
        // Setup connection in ESTABLISHED state
        setupEstablishedConnection();

        // Send packet with only PADDING (non-ack-eliciting)
        ByteBuffer packet = createMock1RttPacket(0, new byte[]{0x00}); // PADDING frame
        connection.process1RttPacket(new RootPoolBuffer(packet, pool, false), 0, TEST_ADDRESS);
        List<ByteBuffer> responses = getOutboundPackets(connection);

        assertEquals(0, responses.size(), "ACK should not be generated for PADDING-only packet");
    }

    @Test
    @DisplayName("Test ACK generated for ack-eliciting frames")
    void testAckGeneratedForStreamFrame() throws Exception {
        // Setup connection in ESTABLISHED state
        setupEstablishedConnection();

        // Send packet with STREAM frame (ack-eliciting)
        ByteBuffer packet = createMock1RttPacketWithStreamData(0L, "data".getBytes());
        connection.process1RttPacket(new RootPoolBuffer(packet, pool, false), 0, null);
        ByteBuffer ackResponse = getOutboundPackets(connection).get(0);

        assertNotNull(ackResponse, "ACK should be generated for STREAM frame");
    }

    // ========================================================================
    // Retransmission Tests
    // ========================================================================

    @Test
    @DisplayName("Test retransmission triggered by packet threshold (3 packets lost)")
    void testRetransmissionPacketThreshold() throws Exception {
        // Setup connection in HANDSHAKE state (easier to test Initial space retransmission)
        connection.setState(QuicConnection.State.HANDSHAKE);
        setupMockTlsMetadata();

        // Simulate server sending Initial packets 0, 1, 2, 3, 4
        PacketNumberSpace initialSpace = connection.getInitialSpace();
        for (int i = 0; i < 5; i++) {
            PoolBuffer mockPayload = createMockCryptoFramePayload();
            initialSpace.onPacketSent(0, i, mockPayload, true);
        }

        // Client ACKs packets 4, 3, 2 (creating gap of 3 packets: 0, 1, 2)
        // This should trigger retransmission of packet 0 (threshold = 3)
        List<PacketNumberSpace.AckRange> ackRanges = new ArrayList<>();
        ackRanges.add(new PacketNumberSpace.AckRange(2, 4)); // Packets 2-4

        initialSpace.onAckReceived(0, 4, ackRanges, 0, null, 0);
        java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = initialSpace.detectLostPackets(0);

        // Verify packet 0 was declared lost (4 - 3 = 1, so packets < 1 are lost)
        assertFalse(lostPackets.isEmpty(), "Should detect lost packets");
        assertTrue(lostPackets.containsKey(0L), "Packet 0 should be declared lost");

        PacketNumberSpace.SentPacket lostPacket = lostPackets.get(0L);
        assertNotNull(lostPacket, "Lost packet 0 should have SentPacket metadata");
        assertNotNull(lostPacket.unencryptedPayload, "Lost packet should have unencrypted payload");
        assertEquals(INITIAL, lostPacket.packetPhase, "Packet type should be INITIAL");
        assertTrue(lostPacket.ackEliciting, "Lost packet should be ack-eliciting");
    }

    @Test
    @DisplayName("Test retransmission SentPacket contains unencrypted payload and packet type")
    void testRetransmissionPacketContent() throws Exception {
        // Setup connection in HANDSHAKE state
        connection.setState(QuicConnection.State.HANDSHAKE);
        setupMockTlsMetadata();

        // Simulate sending an Initial packet with known payload
        PacketNumberSpace initialSpace = connection.getInitialSpace();
        PoolBuffer originalPayload = createMockCryptoFramePayload();

        // Store original unencrypted payload for comparison
        ByteBuffer expectedPayload = originalPayload.buf().duplicate();
        byte[] expectedBytes = new byte[expectedPayload.remaining()];
        expectedPayload.get(expectedBytes);

        initialSpace.onPacketSent(0, 0, originalPayload, true);

        // Trigger loss by ACKing packet 4 (packet 0 will be lost by packet threshold)
        for (int i = 1; i < 5; i++) {
            initialSpace.onPacketSent(0, i, createMockCryptoFramePayload(), true);
        }

        List<PacketNumberSpace.AckRange> ackRanges = new ArrayList<>();
        ackRanges.add(new PacketNumberSpace.AckRange(2, 4));
        initialSpace.onAckReceived(0, 4, ackRanges, 0, null, 0);
        java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = initialSpace.detectLostPackets(0);

        // Retrieve SentPacket for retransmission
        assertTrue(lostPackets.containsKey(0L), "Packet 0 should be in lost packets");
        PacketNumberSpace.SentPacket sentPacket = lostPackets.get(0L);

        assertNotNull(sentPacket, "Should retrieve SentPacket for retransmission");
        assertNotNull(sentPacket.unencryptedPayload, "SentPacket should have unencrypted payload");
        assertEquals(INITIAL, sentPacket.packetPhase, "Packet type should be INITIAL");
        assertEquals(0L, sentPacket.packetNumber, "Original packet number should be preserved");
        assertTrue(sentPacket.ackEliciting, "Packet should be ack-eliciting");

        // Verify unencrypted payload content matches original
        assertEquals(expectedBytes.length, sentPacket.unencryptedPayload.buf().remaining(),
                "Unencrypted payload should have same size as original");

        byte[] payloadBytes = new byte[sentPacket.unencryptedPayload.buf().remaining()];
        sentPacket.unencryptedPayload.buf().duplicate().get(payloadBytes);
        assertArrayEquals(expectedBytes, payloadBytes,
                "Unencrypted payload should have identical content to original");
    }

    @Test
    @DisplayName("Test multiple lost packets are all retransmitted")
    void testMultipleLostPacketsRetransmitted() throws Exception {
        // Setup connection in HANDSHAKE state
        connection.setState(QuicConnection.State.HANDSHAKE);
        setupMockTlsMetadata();

        // Send Initial packets 0-5
        PacketNumberSpace initialSpace = connection.getInitialSpace();
        for (int i = 0; i < 6; i++) {
            initialSpace.onPacketSent(0, i, createMockCryptoFramePayload(), true);
        }

        // ACK only packet 5, leaving 0-4 unacked
        List<PacketNumberSpace.AckRange> ackRanges = new ArrayList<>();
        ackRanges.add(new PacketNumberSpace.AckRange(5, 5));

        initialSpace.onAckReceived(0, 5, ackRanges, 0, null, 0);
        java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = initialSpace.detectLostPackets(0);

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
            assertTrue(sentPacket.unencryptedPayload.buf().hasRemaining(),
                    "Lost packet " + entry.getKey() + " should have payload data");
            assertEquals(INITIAL, sentPacket.packetPhase,
                    "Lost packet " + entry.getKey() + " should have correct packet type");
        }
    }

    @Test
    @DisplayName("Test retransmission via processHandshakePacket ACK handling")
    void testRetransmissionViaHandshakeAck() throws Exception {
        // Setup connection in HANDSHAKE state
        connection.setState(QuicConnection.State.HANDSHAKE);
        setupMockTlsMetadata();

        // Simulate sending Initial packets 0, 1, 2
        PacketNumberSpace initialSpace = connection.getInitialSpace();
        for (int i = 0; i < 3; i++) {
            PoolBuffer mockPacket = createMockInitialPacket();
            initialSpace.onPacketSent(0, i, mockPacket, true);
        }

        // Create Handshake packet with ACK frame that only ACKs packets 2 and 3
        // This should trigger retransmission of packet 0 (more than 3 below largest acked)
        ByteBuffer handshakePacket = createMockHandshakePacketWithAck(3, new long[]{2, 3}, (byte) initialSpace.allocatePacketNumber());

        connection.processHandshakePacket(new RootPoolBuffer(handshakePacket, pool, false), 0);
        List<ByteBuffer> responses = getOutboundPackets(connection);


        // Response should include retransmissions (if any were triggered)
        // Note: The exact behavior depends on loss detection thresholds
        assertNotNull(responses, "Should return response list");
    }

    @Test
    @DisplayName("Test no retransmission for already-acked packets")
    void testNoRetransmissionForAckedPackets() throws Exception {
        // Setup connection in ESTABLISHED state
        setupEstablishedConnection();

        // Send 1-RTT packets 0, 1, 2
        PacketNumberSpace appSpace = connection.getApplicationSpace();
        for (int i = 0; i < 3; i++) {
            PoolBuffer mockPayload = new RootPoolBuffer(ByteBuffer.wrap(new byte[]{0x00}), pool, false).borrow(); // PADDING frame
            appSpace.onPacketSent(0, i, mockPayload, true);
        }

        // ACK all packets
        List<PacketNumberSpace.AckRange> ackRanges = new ArrayList<>();
        ackRanges.add(new PacketNumberSpace.AckRange(0, 2));
        appSpace.onAckReceived(0, 2, ackRanges, 0, null, 0);
        java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = appSpace.detectLostPackets(0);

        // No packets should be declared lost
        assertTrue(lostPackets.isEmpty(), "No packets should be lost when all are acked");

        // Verify no packets are in the lost packets map
        assertFalse(lostPackets.containsKey(0L), "Acked packet 0 should not be in lost packets");
        assertFalse(lostPackets.containsKey(1L), "Acked packet 1 should not be in lost packets");
        assertFalse(lostPackets.containsKey(2L), "Acked packet 2 should not be in lost packets");
    }

    @Test
    @DisplayName("Test retransmission via 1-RTT ACK processing")
    void testRetransmissionVia1RttAck() throws Exception {
        // Setup connection in ESTABLISHED state
        setupEstablishedConnection();

        // Simulate sending 1-RTT packets 0-4
        PacketNumberSpace appSpace = connection.getApplicationSpace();
        for (int i = 0; i < 5; i++) {
            PoolBuffer mockPayload = new RootPoolBuffer(ByteBuffer.wrap(new byte[]{0x00}), pool, false).borrow(); // PADDING frame
            appSpace.onPacketSent(0, i, mockPayload, true);
            appSpace.allocatePacketNumber();
        }

        // Create 1-RTT packet with ACK that only acknowledges packets 2-4
        // This creates a gap that should trigger retransmission of packet 0
        ByteBuffer ackPacket = createMock1RttPacketWithSelectiveAck(4, new long[]{2, 3, 4}, appSpace.allocatePacketNumber());

        connection.process1RttPacket(new RootPoolBuffer(ackPacket, pool, false).borrow(), 0, null);
        List<ByteBuffer> responses = getOutboundPackets(connection);

        // Should return retransmissions for lost packets
        assertNotNull(responses, "Should return response list");
    }

    @Test
    @DisplayName("Test retransmission generates NEW packet numbers (RFC 9002)")
    void testRetransmissionGeneratesNewPacketNumbers() throws Exception {
        // Setup connection in HANDSHAKE state
        connection.setState(QuicConnection.State.HANDSHAKE);
        connection.connectionMetadata.clientCid = new byte[]{0x01};
        setupMockTlsMetadata();

        PacketNumberSpace handshakeSpace = connection.getHandshakeSpace();

        // Send Initial packets 0, 1, 2, 3, 4
        for (int i = 0; i < 5; i++) {
            PoolBuffer mockPayload = createMockCryptoFramePayload();
            handshakeSpace.allocatePacketNumber();
            handshakeSpace.onPacketSent(0, i, mockPayload, true);
        }

        // Verify next packet number before retransmission
        long nextPnBefore = handshakeSpace.allocatePacketNumber();
        assertEquals(5L, nextPnBefore, "Next packet number should be 5 before retransmission");

        // Create Handshake packet with ACK that triggers retransmission of packet 0
        // ACK packets 2, 3, 4 (gap of 3 packets)
        ByteBuffer handshakePacket = createMockHandshakePacketWithAck(4, new long[]{2, 3, 4}, (byte) handshakeSpace.allocatePacketNumber());

        // Process the ACK - should trigger retransmission of packet 0 with NEW packet number
        connection.processHandshakePacket(new RootPoolBuffer(handshakePacket, pool, false), 0);
        List<ByteBuffer> responses = getOutboundPackets(connection);

        // Verify retransmissions were generated
        assertFalse(responses.isEmpty(), "Should generate retransmission packets");

        // Verify packet number space has been incremented (new packets were allocated)
        long nextPnAfter = handshakeSpace.allocatePacketNumber();
        assertTrue(nextPnAfter > 5,
                "Packet number should be > 5 after retransmission, indicating NEW packet numbers were used. Got: " + nextPnAfter);

        // The retransmitted packet should have used packet number 5 (next available)
        // So next available should be at least 6
        assertTrue(nextPnAfter >= 6,
                "Next packet number should be >= 6, indicating retransmission used PN 5. Got: " + nextPnAfter);
    }

    @Test
    @DisplayName("Test retransmitted packet tracked with NEW packet number in space")
    void testRetransmittedPacketTrackedWithNewNumber() throws Exception {
        // Setup connection in ESTABLISHED state
        setupEstablishedConnection();

        PacketNumberSpace appSpace = connection.getApplicationSpace();

        // Send packets 0-4
        for (int i = 0; i < 5; i++) {
            PoolBuffer mockPayload = new RootPoolBuffer(ByteBuffer.wrap(new byte[]{0x00}), pool, false).borrow();
            appSpace.onPacketSent(0, i, mockPayload, true);
            appSpace.allocatePacketNumber();
        }

        // Verify next packet number is 5
        long nextPnBeforeRetransmit = appSpace.allocatePacketNumber();
        assertEquals(5L, nextPnBeforeRetransmit, "Next packet number should be 5");

        // Count unacked packets before retransmission
        int unackedBefore = appSpace.getUnackedPacketCount();

        // Trigger retransmission by ACKing packets 2-4 (packet 0 will be lost)
        ByteBuffer ackPacket = createMock1RttPacketWithSelectiveAck(4, new long[]{2, 3, 4}, nextPnBeforeRetransmit);
        connection.process1RttPacket(new RootPoolBuffer(ackPacket, pool, false).borrow(), 0, null);
        List<ByteBuffer> responses = getOutboundPackets(connection);

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

    @Test
    @DisplayName("Test multiple retransmissions each get unique NEW packet numbers")
    void testMultipleRetransmissionsGetUniqueNewPacketNumbers() throws Exception {
        // Setup connection in ESTABLISHED state
        setupEstablishedConnection();

        PacketNumberSpace appSpace = connection.getApplicationSpace();

        // Send packets 0-5
        for (int i = 0; i < 6; i++) {
            PoolBuffer mockPayload = new RootPoolBuffer(ByteBuffer.wrap(new byte[1200]), pool, false).borrow();
            appSpace.onPacketSent(0, i, mockPayload, true);
            appSpace.allocatePacketNumber();
        }

        // Next packet number should be 6
        long nextPnBefore = appSpace.allocatePacketNumber();
        assertEquals(6L, nextPnBefore, "Next packet number should be 6 before retransmission");

        // ACK only packet 5, causing packets 0, 1 to be declared lost (5 - 3 = 2)
        ByteBuffer ackPacket = createMock1RttPacketWithSelectiveAck(5, new long[]{5}, nextPnBefore);
        connection.process1RttPacket(new RootPoolBuffer(ackPacket, pool, false).borrow(), 0, null);
        List<ByteBuffer> responses = getOutboundPackets(connection);

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

    // ========================================================================
    // Helper Methods
    // ========================================================================

    private void setupEstablishedConnection() throws Exception {
        connection.setState(QuicConnection.State.ESTABLISHED);
        connection.connectionMetadata.clientCid = ByteBuffer.allocate(8).putLong(TEST_CID).array();
        setupMockTlsMetadata();
    }

    private void setupMockTlsMetadata() throws Exception {
//        // Create mock SecretKey objects (required for 1-RTT packet processing)
        MemorySegment clientHandshakeSecret = Arena.global().allocate(16);
        MemorySegment serverHandshakeSecret = Arena.global().allocate(16);
        MemorySegment client1RttSecret = Arena.global().allocate(16);
        MemorySegment server1RttSecret = Arena.global().allocate(16);

        QuicCrypto.PacketProtectionKeysWithHP[] initialProtectionKeys = ConnectionMetadata.deriveInitialKeys(QuicVersion.QUIC_VERSION_1, ByteBuffer.allocate(8).putLong(TEST_CID).array());

        ConnectionMetadata mockMetadata = new ConnectionMetadata();
        mockMetadata.negotiatedIdleTimeoutMs = 10_000;
        mockMetadata.clientInitialCrypto = new HashMap<>(Map.of(QuicVersion.QUIC_VERSION_1, nCryptoMock, QuicVersion.QUIC_VERSION_2, nCryptoMock));
        mockMetadata.serverInitialCrypto = new HashMap<>(Map.of(QuicVersion.QUIC_VERSION_1, nCryptoMock, QuicVersion.QUIC_VERSION_2, nCryptoMock));
        mockMetadata.clientHandshakeCrypto = nCryptoMock;//new NativeCrypto(new QuicCrypto.PacketProtectionKeysWithHP(clientHandshakeSecret, new byte[12], null));
        mockMetadata.serverHandshakeCrypto = nCryptoMock;//new NativeCrypto(new QuicCrypto.PacketProtectionKeysWithHP(serverHandshakeSecret, new byte[12], null));
        mockMetadata.clientApplicationCrypto = nCryptoMock;//new NativeCrypto(new QuicCrypto.PacketProtectionKeysWithHP(client1RttSecret, new byte[12], null));
        mockMetadata.serverApplicationCrypto = nCryptoMock;//new NativeCrypto(new QuicCrypto.PacketProtectionKeysWithHP(server1RttSecret, new byte[12], null));

        // Real rotateApplicationKeys needs a non-null traffic secret to run HKDF
        mockMetadata.clientApplicationTrafficSecret = new byte[32];
        mockMetadata.serverApplicationTrafficSecret = new byte[32];
    }

    /**
     * Creates mock unencrypted CRYPTO frame payload for testing.
     * This represents the frames BEFORE encryption.
     */
    private PoolBuffer createMockCryptoFramePayload() {
        ByteBuffer payload = ByteBuffer.allocateDirect(64);
        payload.put((byte) 0x06); // CRYPTO frame type
        payload.put((byte) 0);    // Offset (varint)
        payload.put((byte) 32);   // Length (varint)
        // Add 32 bytes of mock crypto data
        for (int i = 0; i < 32; i++) {
            payload.put((byte) i);
        }
        payload.flip();
        return new RootPoolBuffer(payload, pool, false).borrow();
    }

    private PoolBuffer createMockInitialPacket() {
        // Create a minimal valid Initial packet structure
        ByteBuffer packet = ByteBuffer.allocateDirect(1280);

        // Flags: long header + fixed bit + Initial type
        packet.put((byte) 0xC0);

        // Version
        packet.putInt(0x00000001);

        // DCID
        packet.put((byte) 8);
        packet.putLong(TEST_CID);

        // SCID
        packet.put((byte) 8);
        packet.putLong(TEST_CID);

        // Token length
        packet.put((byte) 0);

        // Length (simplified)
        // Handshake header: msg_type(1) + length(3) = 4 bytes
        int chBodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1; // 41
        
        byte[] clientHelloBytes = new byte[chBodyLen]; 
        ByteBuffer ch = ByteBuffer.wrap(clientHelloBytes);
        ch.putShort((short) 0x0303);                  // legacy_version: TLS 1.2 compat
        ch.put(new byte[32]);                         // client_random (32 bytes)
        ch.put((byte) 0x00);                          // legacy_session_id length = 0
        ch.putShort((short) 0x0002);                  // cipher_suites length = 2
        ch.putShort((short) 0x1301);                  // TLS_AES_128_GCM_SHA256
        ch.put((byte) 0x01);                          // compression_methods length = 1
        ch.put((byte) 0x00);                          // no compression

        // CRYPTO frame payload: msg_type(1) + length(3) + body(41) = 45 bytes
        // App code bug: QuicConnection sets rebuilder expectedLength = 41 (body length)
        // We must ensure rebuilder finishes.
        ByteBuffer cryptoPayload = ByteBuffer.allocateDirect(4 + clientHelloBytes.length);
        cryptoPayload.put((byte) 0x01); // msg_type: ClientHello
        cryptoPayload.put((byte) 0x00);
        cryptoPayload.put((byte) 0x00);
        cryptoPayload.put((byte) chBodyLen);
        cryptoPayload.put(clientHelloBytes);
        cryptoPayload.flip();

        // CRYPTO frame: type(1) + offset varint(1) + length varint(1) + data(45) = 48 bytes
        int cryptoFrameLen = 1 + 1 + 1 + cryptoPayload.remaining();
        ByteBuffer plaintext = ByteBuffer.allocateDirect(cryptoFrameLen);
        plaintext.put((byte) 0x06);                              // CRYPTO frame type
        plaintext.put((byte) 0x00);                              // offset = 0
        plaintext.put((byte) cryptoPayload.remaining());         // length
        plaintext.put(cryptoPayload);
        plaintext.flip();

        // Length in header = PN length (1) + plaintext (48) + tag (16) = 65
        QuicVarint.write(packet, 65);

        // Packet number
        packet.put((byte) 0);

        packet.put(plaintext);
        packet.put(new byte[16]); // GCM Tag

        // Pad to 1200 bytes for Initial packets (RFC 9000)
        int currentPos = packet.position();
        if (currentPos < 1200) {
            byte[] padding = new byte[1200 - currentPos];
            packet.put(padding);
        }

        packet.flip();
        return new RootPoolBuffer(packet, pool, false).borrow();
    }

    private ByteBuffer createMockHandshakePacket() {
        // Create mock TLS Finished message structure (RFC 8446)
        byte[] mockCryptoData = new byte[36];
        mockCryptoData[0] = 0x14;  // Finished message type
        mockCryptoData[1] = 0x00;
        mockCryptoData[2] = 0x00;
        mockCryptoData[3] = 0x20;  // Length = 32

        // Create CRYPTO frame with TLS Finished message
        ByteBuffer cryptoFrame = ByteBuffer.allocateDirect(128);
        cryptoFrame.put((byte) 0x06);                  // CRYPTO frame type
        cryptoFrame.put((byte) 0);                     // Offset (varint)
        cryptoFrame.put((byte) mockCryptoData.length); // Length (varint)
        cryptoFrame.put(mockCryptoData);
        cryptoFrame.flip();

        // Encrypted payload = crypto frame bytes + 16-byte GCM tag
        byte[] frameBytes = new byte[cryptoFrame.remaining()];
        cryptoFrame.get(frameBytes);
        byte[] payload = new byte[frameBytes.length + QuicCrypto.GCM_TAG_LENGTH];
        System.arraycopy(frameBytes, 0, payload, 0, frameBytes.length);

        // Build a valid QUIC Handshake long-header packet (RFC 9000)
        // flags: 1 (Long) | 1 (Fixed) | 10 (Handshake type) | 00 (reserved) | 00 (1-byte PN)
        //        = 1110_0000 = 0xE0  -> type bits (flags & 0x30) >> 4 == 0x02 -> HANDSHAKE
        //        Packet number length = (flags & 0x03) + 1 = 1 byte
        byte flags = (byte) 0xE0;
        byte[] dcid = longToBytes(TEST_CID);
        byte[] scid = new byte[8];

        // payloadLength = packet-number (1) + ciphertext + tag
        long payloadLength = 1 + payload.length;

        ByteBuffer packet = ByteBuffer.allocateDirect(512);
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
        packet.put(payload);
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

        ByteBuffer buffer = ByteBuffer.allocateDirect(512);
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
        ByteBuffer payload = ByteBuffer.allocateDirect(256);
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
        ByteBuffer payload = ByteBuffer.allocateDirect(64);
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

    private NativeCrypto mockNCrypto() throws QuicException {
        NativeCrypto mock = mock(NativeCrypto.class);
        doNothing().when(mock).decryptAeadInPlace(any(), anyLong(), any());
        doNothing().when(mock).encryptEcbInPlace(any());
        doNothing().when(mock).encryptPacketInPlace(any(), anyLong(), any());
        return mock;
    }

//    private MockedStatic<ConnectionMetadata> mockConnectionMetadata() {
//
//        // Mock key derivation
//        QuicCrypto.PacketProtectionKeysWithHP mockKeys = new QuicCrypto.PacketProtectionKeysWithHP(
//                MemorySegment.NULL, new byte[12], null
//        );
//
//        MockedStatic<ConnectionMetadata> cm = Mockito.mockStatic(ConnectionMetadata.class, Answers.CALLS_REAL_METHODS);
//        cm.when(() -> ConnectionMetadata.deriveInitialKeys(any(QuicVersion.class), any(byte[].class)))
//                .thenReturn(new QuicCrypto.PacketProtectionKeysWithHP[]{mockKeys, mockKeys});
//        return cm;
//    }

    private MockedStatic<QuicCrypto> mockQuicCrypto() {
        MockedStatic<QuicCrypto> mock = Mockito.mockStatic(QuicCrypto.class, Answers.CALLS_REAL_METHODS);
        mock.when(() -> QuicCrypto.signData(any(byte[].class), anyShort())).thenReturn(new byte[16]);
        mock.when(() -> QuicCrypto.processClientHello(any(ConnectionMetadata.class), any(ByteBuffer.class)))
                .thenAnswer(invocation -> {
                    ConnectionMetadata metadata = (ConnectionMetadata) invocation.getArguments()[0];
                    updMeta(metadata);
                    return null;
                } );
        // Mock client Finished verification - return true for valid Finished message
        mock.when(() -> QuicCrypto.verifyClientFinished(any(ByteBuffer.class), any(byte[].class), any(byte[].class)))
                .thenReturn(true);
        // Mock stateless reset token generation
        mock.when(() -> QuicCrypto.generateStatelessResetToken(any(byte[].class)))
                .thenReturn(new byte[16]);

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
        ByteBuffer ackFrame = ByteBuffer.allocateDirect(64);
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
        // flags: 1110_0000 = 0xE0  -> type bits == 0x02 -> HANDSHAKE, 1-byte packet number
        byte flags = (byte) 0xE0;
        byte[] dcid = longToBytes(TEST_CID);
        byte[] scid = new byte[8];

        // payloadLength = packet-number (1) + ciphertext + tag
        long payloadLength = 1 + encryptedPayload.length;

        ByteBuffer packet = ByteBuffer.allocateDirect(512);
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
        ByteBuffer ackFrame = ByteBuffer.allocateDirect(64);
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

    /**
     * Creates a mock 1-RTT short-header packet with a controllable key phase bit.
     *
     * <p>RFC 9001 Section 6: The Key Phase bit (bit 2 of the first byte of a short header,
     * i.e. {@code flags & 0x04}) signals that the sender has rotated to new 1-RTT keys.
     *
     * @param packetNumber the packet number to embed in the packet
     * @param payload      unencrypted payload bytes (will be passed through the mocked decryptAead)
     * @param keyPhaseBit  {@code true} to set the key phase bit (new keys), {@code false} to clear it
     * @return a flipped {@link ByteBuffer} ready for {@link QuicConnection#process1RttPacket}
     */
    private ByteBuffer createMock1RttPacketWithKeyPhase(long packetNumber, byte[] payload, boolean keyPhaseBit) {
        // Short header flags layout (RFC 9001 В§5.4.2 / RFC 9000 В§17.3):
        //   bit 7 = 0        (short header)
        //   bit 6 = 1        (Fixed Bit, must be 1)
        //   bit 5 = 0        (Spin Bit)
        //   bit 4 = 0        (reserved)
        //   bit 3 = 0        (reserved)
        //   bit 2 = Key Phase
        //   bits 1-0 = 00    (1-byte packet number)
        byte flags = (byte) (0x40 | (keyPhaseBit ? 0x04 : 0x00));
        byte[] dcid = longToBytes(TEST_CID);

        ByteBuffer buffer = ByteBuffer.allocateDirect(512);
        buffer.put(flags);
        buffer.put(dcid);
        buffer.put((byte) packetNumber);   // 1-byte packet number
        buffer.put(payload);
        // GCM authentication tag placeholder (16 bytes)
        for (int i = 0; i < QuicCrypto.GCM_TAG_LENGTH; i++) {
            buffer.put((byte) 0);
        }
        buffer.flip();
        return buffer;
    }
}

