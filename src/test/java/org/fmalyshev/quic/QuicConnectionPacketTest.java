package org.fmalyshev.quic;

import org.fmalyshev.quic.buffers.BorrowedPoolBuffer;
import org.fmalyshev.quic.buffers.PoolBuffer;
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

/**
 * Integration tests for QuicConnection packet generation with proper headers.
 */
class QuicConnectionPacketTest {

    private QuicConnection connection;
    private static final long TEST_CONNECTION_ID = 0x00239L;
    private static final InetSocketAddress TEST_ADDRESS = new InetSocketAddress("127.0.0.1", 4433);
    private MockedStatic<QuicCrypto> mockedQuicCrypto;

    @BeforeEach
    void setUp() {
        connection = new QuicConnection(TEST_CONNECTION_ID, TEST_ADDRESS);

        // Mock QuicCrypto static methods to bypass actual cryptographic operations
        mockedQuicCrypto = mockStatic(QuicCrypto.class);
        setupCryptoMocks();
    }

    @AfterEach
    void tearDown() {
        if (mockedQuicCrypto != null) {
            mockedQuicCrypto.close();
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
        mockedQuicCrypto.when(() -> QuicCrypto.decryptAead(any(ByteBuffer.class), any(SecretKey.class), 
                                                           any(byte[].class), anyLong(), any(ByteBuffer.class), any()))
            .thenAnswer(invocation -> {
                ByteBuffer input = invocation.getArgument(0);
                ByteBuffer output = invocation.getArgument(4);
                // Bypass encryption: copy available input to output
                int bytesToCopy = Math.min(input.remaining(), output.remaining());
                if (bytesToCopy > 0) {
                    byte[] data = new byte[bytesToCopy];
                    input.get(data);
                    output.put(data);
                }
                return null;
            });

        // Mock ClientHello processing — use new single-arg constructor, set fields directly
        QuicCrypto.TlsMetadata mockMetadata = new QuicCrypto.TlsMetadata();
        mockMetadata.clientRandom            = new byte[32];
        mockMetadata.serverRandom            = new byte[32];
        mockMetadata.selectedCipherSuite     = "TLS_AES_128_GCM_SHA256";
        mockMetadata.alpn                    = "h3";
        mockMetadata.negotiatedIdleTimeoutMs = 10_000;
        mockMetadata.serverEphemeralPublicKey = new byte[32];
        mockMetadata.clientMetadata = new QuicCrypto.ParsedClientHello("h3", 1000, List.of(), Map.of(), 10000, 1000, List.of());
        QuicCrypto.PacketProtectionKeysWithHP mockKeyss = new QuicCrypto.PacketProtectionKeysWithHP(mockKey, new byte[16], null);

        mockMetadata.setApplicationKeys(new QuicCrypto.PacketProtectionKeys(mockKey, new byte[16]), new QuicCrypto.PacketProtectionKeys(mockKey, new byte[16]));
        mockMetadata.serverHandshakeKeys = mockKeyss;
        mockMetadata.clientHandshakeKeys = mockKeyss;

        mockedQuicCrypto.when(() -> QuicCrypto.getCryptoFrameLength(any())).thenCallRealMethod();
        mockedQuicCrypto.when(() -> QuicCrypto.processClientHello(any(), any(ByteBuffer.class)))
            .thenReturn(mockMetadata);

        // Mock ServerHello creation — single TlsMetadata arg
        mockedQuicCrypto.when(() -> QuicFrameBuilder.writeServerHello(any(), any(QuicCrypto.TlsMetadata.class)))
            .thenReturn(ByteBuffer.wrap(new byte[100]));

        // Mock deriveApplicationKeys (called inside processHandshakePacket after Finished)
        mockedQuicCrypto.when(() -> QuicCrypto.createApplicationKeys(any(QuicCrypto.TlsMetadata.class)))
            .thenAnswer(invocation -> {
                // No-op: application keys are already set on mockMetadata above
                return null;
            });

        // Mock client Finished verification
        mockedQuicCrypto.when(() -> QuicCrypto.verifyClientFinished(any(),
                                                                    any(),
                                                                    any()))
            .thenReturn(true);

        // Mock encryption to bypass encryption - symmetrical to decryptAead
        mockedQuicCrypto.when(() -> QuicCrypto.encryptPacket(any(ByteBuffer.class),
                                                             any(SecretKey.class),
                                                             anyLong(),
                                                             any(),
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
        connection.processInitialAndRespond(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), mockInitialPacket));
        List<ByteBuffer> responses = getOutboundPackets(connection);

        // Assert
        assertFalse(responses.isEmpty(), "Initial response should not be null");
        assertTrue(responses.get(0).hasRemaining(), "Response should have data");

        // Verify it's an Initial packet (long header, type 00)
        byte flags = responses.get(0).get(0);
        assertEquals(0x80, flags & 0x80, "Should have long header bit set");
        assertEquals(0x40, flags & 0x40, "Should have fixed bit set");
        assertEquals(0x00, (flags & 0x30) >> 4, "Should be Initial packet type");

        // Verify version
        int version = responses.get(0).getInt(1);
        assertEquals(0x00000001, version, "Should be QUIC version 1");

        // Verify connection ID is present
        responses.get(0).position(5); // Skip flags + version
        byte dcidLen = responses.get(0).get();
        assertEquals(8, dcidLen, "DCID length should be 8");
        long dcid = responses.get(0).getLong();
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
        connection.processHandshakePacket(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), mockHandshakePacket));
        List<ByteBuffer> responses = getOutboundPackets(connection);

        // Assert
        assertNotNull(responses);
        assertEquals(2, responses.size(), "Should return Handshake + HANDSHAKE_DONE packets");

        // Verify second packet is 1-RTT (short header)
        ByteBuffer donePacket = responses.get(0);
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
        connection.process1RttPacket(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), mock1RttPacket));
        ByteBuffer ackPacket = connection.pollOutbound().buf();


        // Assert
        if (ackPacket != null) { // ACK might not be generated for all packets
            byte flags = ackPacket.get(0);

            // Verify short header
            assertEquals(0x00, flags & 0x80, "1-RTT ACK should have short header");
            assertEquals(0x40, flags & 0x40, "Should have fixed bit set");

            // Verify CID is present
            ackPacket.position(1);
            long cid = ackPacket.getLong();
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
         connection.processInitialAndRespond(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), invalidInitial));
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
        connection.processInitialAndRespond(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), mockInitial));
        List<ByteBuffer> responses = getOutboundPackets(connection);

        // Assert - verify both DCID and SCID contain the connection ID
        responses.get(0).position(5); // Skip flags + version

        byte dcidLen = responses.get(0).get();
        assertEquals(8, dcidLen);
        long dcid = responses.get(0).getLong();
        assertEquals(TEST_CONNECTION_ID, dcid, "DCID should be connection ID");

        byte scidLen = responses.get(0).get();
        assertEquals(8, scidLen);
        long scid = responses.get(0).getLong();
        assertEquals(TEST_CONNECTION_ID, scid, "SCID should be connection ID (server uses same)");
    }

    @Test
    void testInitialPacket_HasZeroTokenLength() {
        // Arrange
        ByteBuffer mockInitial = createMockInitialPacket();

        // Act
        connection.processInitialAndRespond(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), mockInitial));
        List<ByteBuffer> responses = getOutboundPackets(connection);

        // Assert - skip to token length field
        responses.get(0).position(1 + 4 + 1 + 8 + 1 + 8); // flags + version + dcid_len + dcid + scid_len + scid

        byte tokenLen = responses.get(0).get();
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

        // Length (simplified - 100 bytes)
        QuicVarint.write(packet, 100);

        // Packet number
        packet.put((byte) 0);

        // Plaintext payload: CRYPTO frame with a minimal valid TLS 1.3 ClientHello.
        // decryptAead is mocked to pass bytes straight through, so this plaintext is
        // fed directly to the frame parser and must be structurally correct.
        //
        // Minimal ClientHello body:
        //   legacy_version(2) + random(32) + session_id_len(1)
        //   + cipher_suites_len(2) + cipher_suite(2)          = TLS_AES_128_GCM_SHA256
        //   + compression_methods_len(1) + compression(1)
        //   = 41 bytes
        // Handshake header: msg_type(1) + length(3) = 4 bytes  →  total = 45 bytes
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
        int cryptoFrameLen = 1 + 1 + 1 + clientHelloBytes.length;
        ByteBuffer plaintext = ByteBuffer.allocate(cryptoFrameLen);
        plaintext.put((byte) 0x06);                              // CRYPTO frame type
        plaintext.put((byte) 0x00);                              // offset = 0
        plaintext.put((byte) clientHelloBytes.length);           // length
        plaintext.put(clientHelloBytes);
        plaintext.flip();

        packet.put(plaintext);
//        packet.put(new byte[16]); // GCM tag (stripped by mocked decryptAead)

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
        connection.processInitialAndRespond(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), mockInitial));

        assertEquals(QuicConnection.State.HANDSHAKE, connection.getState(), 
                    "Connection should be in HANDSHAKE state");
    }

    private void setupConnectionInEstablishedState() throws Exception {
        setupConnectionInHandshakeState();

        // Process Handshake to move to ESTABLISHED
        ByteBuffer mockHandshake = createMockHandshakePacket();
        connection.processHandshakePacket(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), mockHandshake));

        assertEquals(QuicConnection.State.ESTABLISHED, connection.getState(), 
                    "Connection should be in ESTABLISHED state");
    }
}
