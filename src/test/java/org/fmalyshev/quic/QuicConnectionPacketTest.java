package org.fmalyshev.quic;

import org.fmalyshev.quic.buffers.PoolBuffer;
import org.fmalyshev.quic.buffers.BorrowedPoolBuffer;
import org.fmalyshev.quic.buffers.RootPoolBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

import static org.fmalyshev.quic.QuicConnectionCryptoIntegrationTest.getOutboundPackets;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.withSettings;

/**
 * Integration tests for QuicConnection packet generation with proper headers.
 */
class QuicConnectionPacketTest {

    private QuicConnection connection;
    private SelectorThread selectorMock;
    private static final long TEST_CONNECTION_ID = 0x00239L;
    private static final InetSocketAddress TEST_ADDRESS = new InetSocketAddress("127.0.0.1", 4433);
    private MockedStatic<QuicCrypto> mockedQuicCrypto;
    private MockedStatic<QuicFrameBuilder> mockedQuicFrameBuilder;

    @BeforeEach
    void setUp() {
        selectorMock = mock(SelectorThread.class, withSettings().lenient());
        connection = new QuicConnection(TEST_CONNECTION_ID, TEST_ADDRESS, selectorMock);

        // Mock QuicCrypto static methods to bypass actual cryptographic operations
        mockedQuicCrypto = mockStatic(QuicCrypto.class);
        mockedQuicFrameBuilder = mockStatic(QuicFrameBuilder.class);
        setupCryptoMocks();
    }

    @AfterEach
    void tearDown() {
        if (mockedQuicCrypto != null) {
            mockedQuicCrypto.close();
        }
        if (mockedQuicFrameBuilder != null) {
            mockedQuicFrameBuilder.close();
        }
    }

    private void setupCryptoMocks() {
        // Mock key derivation
        SecretKey mockKey = new SecretKeySpec(new byte[16], "AES");
        byte[] mockIv = new byte[12];
        byte[] mockHeaderProtection = null;
        QuicCrypto.PacketProtectionKeysWithHP mockKeys = new QuicCrypto.PacketProtectionKeysWithHP(mockKey, mockIv, mockHeaderProtection);

        mockedQuicCrypto.when(() -> QuicCrypto.deriveInitialKeys(any(byte[].class)))
            .thenReturn(new QuicCrypto.PacketProtectionKeysWithHP[]{mockKeys, mockKeys});

        // Mock decryption to bypass encryption - just copy input to output
        mockedQuicCrypto.when(() -> QuicCrypto.decryptAead(any(ByteBuffer.class), any(javax.crypto.SecretKey.class),
                                                           any(byte[].class), anyLong(), any(ByteBuffer.class), any(byte[].class)))
            .thenAnswer(invocation -> {
                ByteBuffer packet = invocation.getArgument(0);
                ByteBuffer output = invocation.getArgument(4);
                
                // Copy all but last 16 bytes (mock GCM tag) to output
                ByteBuffer duplicate = packet.duplicate();
                if (duplicate.remaining() > 16) {
                    duplicate.limit(duplicate.limit() - 16);
                }
                output.put(duplicate);
                return null;
            });

        // Mock ClientHello processing — use new single-arg constructor, set fields directly
        QuicCrypto.TlsMetadata mockMetadata = new QuicCrypto.TlsMetadata();
        mockMetadata.negotiatedIdleTimeoutMs = 10_000;
        mockMetadata.serverEphemeralPublicKey = new byte[32];
        mockMetadata.clientMetadata = new QuicCrypto.ClientMetadataNegotiated("h3", 1000, List.of(), Map.of(), 1200, 1000, 0, 0, 0, 0, 0, List.of());
        QuicCrypto.PacketProtectionKeysWithHP mockKeyss = new QuicCrypto.PacketProtectionKeysWithHP(mockKey, new byte[16], null);

        mockMetadata.setApplicationKeys(new QuicCrypto.PacketProtectionKeys(mockKey, new byte[16]), new QuicCrypto.PacketProtectionKeys(mockKey, new byte[16]));
        mockMetadata.serverHandshakeKeys = mockKeyss;
        mockMetadata.clientHandshakeKeys = mockKeyss;

        mockedQuicCrypto.when(() -> QuicCrypto.getCryptoFrameLength(any(ByteBuffer.class))).thenCallRealMethod();
        mockedQuicCrypto.when(() -> QuicCrypto.processClientHello(any(QuicCrypto.TlsMetadata.class), any(ByteBuffer.class)))
            .thenReturn(mockMetadata);

        // Mock ServerHello creation — single TlsMetadata arg
        mockedQuicFrameBuilder.when(() -> QuicFrameBuilder.writeServerHello(any(org.fmalyshev.quic.buffers.ChunkedOutputStreamWithAmendments.class), any(QuicCrypto.TlsMetadata.class)))
            .thenAnswer(_ -> null );

        mockedQuicFrameBuilder.when(() -> QuicFrameBuilder.writeConnectionCloseFrame(any(), anyLong(), any()))
                .thenCallRealMethod();

        // Mock deriveApplicationKeys (called inside processHandshakePacket after Finished)
        mockedQuicCrypto.when(() -> QuicCrypto.createApplicationKeys(any(QuicCrypto.TlsMetadata.class)))
            .thenAnswer(invocation -> {
                // No-op: application keys are already set on mockMetadata above
                return null;
            });

        // Mock client Finished verification
        mockedQuicCrypto.when(() -> QuicCrypto.verifyClientFinished(any(ByteBuffer.class),
                                                                    any(byte[].class),
                                                                    any(byte[].class)))
            .thenReturn(true);

        // Mock encryption to bypass encryption - symmetrical to decryptAead
        mockedQuicCrypto.when(() -> QuicCrypto.encryptPacketInPlace(any(ByteBuffer.class),
                                                             any(javax.crypto.SecretKey.class),
                                                             anyLong(),
                                                             nullable(ByteBuffer.class),
                                                             any(byte[].class)))
            .thenAnswer(invocation -> {
                ByteBuffer plaintext = invocation.getArgument(0);
                // Bypass encryption: copy plaintext and append mock GCM tag
                ByteBuffer encrypted = ByteBuffer.allocate(plaintext.remaining() + 16);
                encrypted.put(plaintext.duplicate());
                encrypted.put(new byte[16]); // Mock GCM tag
                encrypted.flip();
                return encrypted;
            });

        // Mock certificate chain encoding
        mockedQuicCrypto.when(() -> QuicCrypto.encodeCertificateChain())
            .thenReturn(new byte[512]);

        // Mock data signing
        mockedQuicCrypto.when(() -> QuicCrypto.signData(any(byte[].class), anyShort()))
            .thenReturn(new byte[64]);
    }

    @Test
    void testProcessInitialAndRespond_CreatesValidInitialPacket() {
        // Arrange - create a mock Initial packet
        ByteBuffer mockInitialPacket = createMockInitialPacket();

        // Act
        connection.processInitialAndRespond(new RootPoolBuffer(mockInitialPacket, false));
        List<ByteBuffer> responses = getOutboundPackets(connection);

        // Assert
        assertFalse(responses.isEmpty(), "Initial response should not be null");
        ByteBuffer response = responses.get(0);
        assertTrue(response.hasRemaining(), "Response should have data");

        // Verify it's an Initial packet (long header, type 00)
        byte flags = response.get(0);
        assertEquals(0x80, flags & 0x80, "Should have long header bit set");
        assertEquals(0x40, flags & 0x40, "Should have fixed bit set");
        assertEquals(0x00, (flags & 0x30) >> 4, "Should be Initial packet type");

        // Verify version
        int version = response.getInt(1);
        System.out.println("[DEBUG_LOG] testProcessInitialAndRespond flags=" + String.format("%02x", flags) + " version=" + String.format("%08x", version));
        assertEquals(0x00000001, version, "Should be QUIC version 1");

        // Verify connection ID is present
        response.position(5); // Skip flags + version
        byte dcidLen = response.get();
        assertEquals(8, dcidLen, "DCID length should be 8");
        byte[] dcidBytes = new byte[8];
        response.get(dcidBytes);
        long dcid = ByteBuffer.wrap(dcidBytes).getLong();
        assertEquals(TEST_CONNECTION_ID, dcid, "DCID should match connection ID");
    }

    @Test
    void testProcessHandshakePacket_CreatesValidHandshakeAndDonePackets() throws Exception {
        // Arrange - set up connection in HANDSHAKE state
        setupConnectionInHandshakeState();

        // Create mock Handshake packet
        ByteBuffer mockHandshakePacket = createMockHandshakePacket();

        // Act
        getOutboundPackets(connection);
        connection.processHandshakePacket(new RootPoolBuffer(mockHandshakePacket, false));
        List<ByteBuffer> responses = getOutboundPackets(connection);

        // Assert
        assertNotNull(responses);
        // We expect Handshake packet (containing Certificate, etc.) followed by HANDSHAKE_DONE (1-RTT)
        // Handshake flight might be multiple packets depending on size, but here we expect at least 1 Handshake and 1 1-RTT
        assertTrue(responses.size() >= 2, "Should return Handshake + HANDSHAKE_DONE packets, but got " + responses.size());

        // Verify second packet is 1-RTT (short header)
        ByteBuffer donePacket = responses.get(responses.size() - 1);
        byte doneFlags = donePacket.get(0);
        assertEquals(0x00, doneFlags & 0x80, "HANDSHAKE_DONE packet should have short header");
        assertEquals(0x40, doneFlags & 0x40, "Should have fixed bit set");
    }

    @Test
    void testProcess1RttPacket_CreatesValid1RttAckPacket() throws Exception {
        // Arrange - set up connection in ESTABLISHED state
        setupConnectionInEstablishedState();

        // Create mock 1-RTT packet
        ByteBuffer mock1RttPacket = createMock1RttPacket();

        // Act
        getOutboundPackets(connection);
        connection.process1RttPacket(new RootPoolBuffer(mock1RttPacket, false), 0);
        PoolBuffer outbound = connection.pollOutbound();
        assertNotNull(outbound, "Should have outbound ACK packet");
        ByteBuffer ackPacket = outbound.buf();


        // Assert
        if (ackPacket != null) { // ACK might not be generated for all packets
            byte flags = ackPacket.get(0);

            // Verify short header
            assertEquals(0x00, flags & 0x80, "1-RTT ACK should have short header");
            assertEquals(0x40, flags & 0x40, "Should have fixed bit set");

            // Verify CID is present
            ackPacket.position(1);
            byte[] cidBytes = new byte[8];
            ackPacket.get(cidBytes);
            long cid = ByteBuffer.wrap(cidBytes).getLong();
            assertEquals(TEST_CONNECTION_ID, cid, "CID should match connection ID");

            // Verify packet number is present
            byte pn = ackPacket.get();
            assertTrue(pn >= 0, "Packet number should be present");

            // Verify there's encrypted payload
            assertTrue(ackPacket.hasRemaining(), "Should have encrypted ACK frame payload");
        }
    }

    @Disabled("Let deside how to handle invalid hello later")
    @Test
    void testConnectionClosePacket_HasProperInitialHeader() throws Exception {
        // Arrange - trigger CONNECTION_CLOSE by processing invalid ClientHello
        ByteBuffer invalidInitial = createInvalidInitialPacket();

        // Act
         connection.processInitialAndRespond(new RootPoolBuffer(invalidInitial, false));
        List<ByteBuffer> closePackets = getOutboundPackets(connection);

        // Assert
        assertFalse(closePackets.isEmpty());

        byte flags = closePackets.get(0).get(0);
        assertEquals(0x80, flags & 0x80, "CONNECTION_CLOSE should use long header (Initial)");
        assertEquals(0x40, flags & 0x40, "Should have fixed bit set");

        // Should be in CLOSING state
        assertEquals(QuicConnection.State.CLOSING, connection.getState());
    }

    @Test
    void testPacketHeaders_ContainCorrectConnectionId() {
        // Arrange
        ByteBuffer mockInitial = createMockInitialPacket();

        // Act
        connection.processInitialAndRespond(new RootPoolBuffer(mockInitial, false));
        List<ByteBuffer> responses = getOutboundPackets(connection);

        // Assert - verify both DCID and SCID contain the connection ID
        ByteBuffer response = responses.get(0);
        response.position(5); // Skip flags + version

        byte dcidLen = response.get();
        assertEquals(8, dcidLen);
        byte[] dcidBytes = new byte[8];
        response.get(dcidBytes);
        long dcid = ByteBuffer.wrap(dcidBytes).getLong();
        assertEquals(TEST_CONNECTION_ID, dcid, "DCID should be connection ID");

        byte scidLen = response.get();
        assertEquals(8, scidLen);
        byte[] scidBytes = new byte[8];
        response.get(scidBytes);
        long scid = ByteBuffer.wrap(scidBytes).getLong();
        assertEquals(TEST_CONNECTION_ID, scid, "SCID should be connection ID (server uses same)");
    }

    @Test
    void testInitialPacket_HasZeroTokenLength() {
        // Arrange
        ByteBuffer mockInitial = createMockInitialPacket();

        // Act
        connection.processInitialAndRespond(new RootPoolBuffer(mockInitial, false));
        List<ByteBuffer> responses = getOutboundPackets(connection);

        // Assert - skip to token length field
        ByteBuffer response = responses.get(0);
        response.position(1 + 4 + 1 + 8 + 1 + 8); // flags + version + dcid_len + dcid + scid_len + scid

        byte tokenLen = response.get();
        assertEquals(0, tokenLen, "Server Initial should have zero token length");
    }

    // Helper methods

    private ByteBuffer createMockInitialPacket() {
        // Create a minimal valid Initial packet structure
        ByteBuffer packet = ByteBuffer.allocate(512);

        // Flags: long header + fixed bit + Initial type
        packet.put((byte) 0xC0);

        // Version
        packet.putInt(0x00000001);

        // DCID
        packet.put((byte) 8);
        packet.putLong(TEST_CONNECTION_ID);

        // SCID
        packet.put((byte) 8);
        packet.putLong(TEST_CONNECTION_ID);

        // Token length
        packet.put((byte) 0);

        // Length (packet number + payload + tag)
        // chBodyLen(41) + header(4) = 45. Crypto frame: 1+1+1+45 = 48.
        // PN (1) + Tag (16) = 17. Total length = 48 + 17 = 65.
        QuicVarint.write(packet, 65);

        // Packet number
        packet.put((byte) 0);

        // Plaintext payload: CRYPTO frame with a minimal valid TLS 1.3 ClientHello.
        int chBodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1; // 41
        byte[] clientHelloBytes = new byte[4 + chBodyLen];
        ByteBuffer ch = ByteBuffer.wrap(clientHelloBytes);
        ch.put((byte) 0x01);                          // msg_type: ClientHello
        ch.put((byte) 0x00);                          // length (3 bytes, big-endian)
        ch.put((byte) ((chBodyLen >> 8) & 0xFF));
        ch.put((byte) (chBodyLen & 0xFF));
        ch.putShort((short) 0x0303);                  // legacy_version: TLS 1.2 compat
        ch.put(new byte[32]);                         // client_random (32 bytes)
        ch.put((byte) 0x00);                          // legacy_session_id length = 0
        ch.putShort((short) 0x0002);                  // cipher_suites length = 2
        ch.putShort((short) 0x1301);                  // TLS_AES_128_GCM_SHA256
        ch.put((byte) 0x01);                          // compression_methods length = 1
        ch.put((byte) 0x00);                          // no compression

        // CRYPTO frame: type(1) + offset varint(1) + length varint(1) + data
        ByteBuffer plaintext = ByteBuffer.allocate(1 + 1 + 1 + clientHelloBytes.length);
        plaintext.put((byte) 0x06);                              // CRYPTO frame type
        plaintext.put((byte) 0x00);                              // offset = 0
        plaintext.put((byte) clientHelloBytes.length);           // length
        plaintext.put(clientHelloBytes);
        plaintext.flip();

        packet.put(plaintext);
        packet.put(new byte[16]); // GCM tag

        packet.flip();
        return packet;
    }

    private ByteBuffer createMockHandshakePacket() {
        ByteBuffer packet = ByteBuffer.allocate(256);

        // Flags: long header + fixed bit + Handshake type (10)
        packet.put((byte) 0xE0);

        // Version
        packet.putInt(0x00000001);

        // DCID
        packet.put((byte) 8);
        packet.putLong(TEST_CONNECTION_ID);

        // SCID
        packet.put((byte) 8);
        packet.putLong(0xFEDCBA9876543210L);

        // Length (packet number + plaintext + GCM tag)
        packet.put((byte) 50);

        // Packet number
        packet.put((byte) 1);

        // Plaintext payload: CRYPTO frame with client Finished
        // 50 - 1 (pn) - 16 (tag) = 33 bytes for plaintext
        // CRYPTO frame: 1 (type) + 1 (offset) + 1 (length) + 36 (data) = 39 bytes
        // But we only have 33 bytes, so adjust:
        // CRYPTO frame: 1 (type) + 1 (offset) + 1 (length) + 30 (TLS Finished) = 33 bytes
        ByteBuffer plaintext = ByteBuffer.allocate(33);

        // CRYPTO frame with client Finished message
        plaintext.put((byte) 0x06); // CRYPTO frame type
        plaintext.put((byte) 0x00); // offset (varint)
        plaintext.put((byte) 30);   // length (varint) - TLS Finished message size

        // TLS Finished message: type(1) + length(3) + verify_data(26 to fit in 30 bytes)
        plaintext.put((byte) 0x14); // Finished message type
        plaintext.put((byte) 0x00); // Length MSB
        plaintext.put((byte) 0x00);
        plaintext.put((byte) 0x1A); // Length = 26 bytes (to fit total 30)
        plaintext.put(new byte[26]); // verify_data

        packet.put(plaintext.array());
        packet.put(new byte[16]); // GCM tag

        packet.flip();
        return packet;
    }

    private ByteBuffer createMock1RttPacket() {
        ByteBuffer packet = ByteBuffer.allocate(128);

        // Flags: short header + fixed bit
        packet.put((byte) 0x40);

        // CID
        packet.putLong(TEST_CONNECTION_ID);

        // Packet number
        packet.put((byte) 5);

        // Plaintext payload: STREAM frame with some data
        ByteBuffer plaintext = ByteBuffer.allocate(100);

        // STREAM frame: type(0x0e) | stream_id(varint) | offset(varint) | length(varint) | data
        plaintext.put((byte) 0x0e); // STREAM frame with Length + Offset bits
        plaintext.put((byte) 0x00); // stream_id = 0
        plaintext.put((byte) 0x00); // offset = 0
        plaintext.put((byte) 10);   // length = 10
        plaintext.put("HelloWorld".getBytes()); // Stream data

        // Padding to fill remaining space
        while (plaintext.hasRemaining()) {
            plaintext.put((byte) 0x00); // PADDING frame
        }

        packet.put(plaintext.array());
        packet.put(new byte[16]); // GCM tag

        packet.flip();
        return packet;
    }

    private ByteBuffer createInvalidInitialPacket() {
        // Create Initial packet that will fail ClientHello processing
        // We'll need to temporarily override the processClientHello mock
        mockedQuicCrypto.when(() -> QuicCrypto.processClientHello(any(), any(ByteBuffer.class)))
            .thenThrow(new QuicCrypto.CryptoException("Invalid ClientHello"));

        return createMockInitialPacket();
    }

    private void setupConnectionInHandshakeState() throws Exception {
        // Process Initial to move to HANDSHAKE state
        ByteBuffer mockInitial = createMockInitialPacket();
        connection.processInitialAndRespond(new RootPoolBuffer(mockInitial, false));

        assertEquals(QuicConnection.State.HANDSHAKE, connection.getState(), 
                    "Connection should be in HANDSHAKE state");
    }

    private void setupConnectionInEstablishedState() throws Exception {
        setupConnectionInHandshakeState();

        // Process Handshake to move to ESTABLISHED
        ByteBuffer mockHandshake = createMockHandshakePacket();
        connection.processHandshakePacket(new RootPoolBuffer(mockHandshake, false));

        assertEquals(QuicConnection.State.ESTABLISHED, connection.getState(), 
                    "Connection should be in ESTABLISHED state");
    }
}
