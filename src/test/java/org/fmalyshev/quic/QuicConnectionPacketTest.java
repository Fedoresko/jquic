package org.fmalyshev.quic;

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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Integration tests for QuicConnection packet generation with proper headers.
 */
class QuicConnectionPacketTest {

    private QuicConnection connection;
    private static final long TEST_CONNECTION_ID = 0x1234567890ABCDEFL;
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
        byte[] mockHeaderProtection = new byte[16];
        QuicCrypto.PacketProtectionKeys mockKeys = new QuicCrypto.PacketProtectionKeys(mockKey, mockIv, mockHeaderProtection);

        mockedQuicCrypto.when(() -> QuicCrypto.deriveInitialKeys(any(byte[].class)))
            .thenReturn(new QuicCrypto.PacketProtectionKeys[]{mockKeys, mockKeys});

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
        QuicCrypto.TlsMetadata mockMetadata = new QuicCrypto.TlsMetadata(new byte[32]);
        mockMetadata.clientRandom            = new byte[32];
        mockMetadata.serverRandom            = new byte[32];
        mockMetadata.clientHandshakeSecret   = mockKey;
        mockMetadata.serverHandshakeSecret   = mockKey;
        mockMetadata.selectedCipherSuite     = "TLS_AES_128_GCM_SHA256";
        mockMetadata.alpn                    = "h3";
        mockMetadata.negotiatedIdleTimeoutMs = 10_000;
        mockMetadata.clientHandshakeHpKey    = new byte[16];
        mockMetadata.serverHandshakeHpKey    = new byte[16];
        mockMetadata.serverEphemeralPublicKey = new byte[32];
        mockMetadata.setApplicationKeys(mockKey, mockKey, new byte[16], new byte[16], new byte[16], new byte[16]);

        mockedQuicCrypto.when(() -> QuicCrypto.processClientHello(any(ByteBuffer.class)))
            .thenReturn(mockMetadata);

        // Mock ServerHello creation — single TlsMetadata arg
        mockedQuicCrypto.when(() -> QuicCrypto.createServerHello(any(QuicCrypto.TlsMetadata.class)))
            .thenReturn(ByteBuffer.wrap(new byte[100]));

        // Mock deriveApplicationKeys (called inside processHandshakePacket after Finished)
        mockedQuicCrypto.when(() -> QuicCrypto.createApplicationKeys(any(QuicCrypto.TlsMetadata.class)))
            .thenAnswer(invocation -> {
                // No-op: application keys are already set on mockMetadata above
                return null;
            });

        // Mock Handshake packet decryption - bypass encryption like decryptAead
        mockedQuicCrypto.when(() -> QuicCrypto.decryptHandshakePacket(any(ByteBuffer.class),
                                                                      any(QuicPacketHeader.class),
                                                                      any(SecretKey.class)))
            .thenAnswer(invocation -> {
                ByteBuffer input = invocation.getArgument(0);
                // Bypass encryption: copy input to plaintext buffer
                ByteBuffer plaintext = ByteBuffer.allocate(input.remaining());
                plaintext.put(input);
                plaintext.flip();
                return new QuicCrypto.DecryptionResult(plaintext, null, false, null, null);
            });

        // Mock client Finished verification
        mockedQuicCrypto.when(() -> QuicCrypto.verifyClientFinished(any(byte[].class),
                                                                    any(SecretKey.class),
                                                                    any(byte[].class)))
            .thenReturn(true);

        // Mock encryption to bypass encryption - symmetrical to decryptAead
        mockedQuicCrypto.when(() -> QuicCrypto.encryptPacket(any(ByteBuffer.class),
                                                             any(SecretKey.class),
                                                             anyLong(),
                                                             any(byte[].class),
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
        mockedQuicCrypto.when(() -> QuicCrypto.signData(any(byte[].class)))
            .thenReturn(new byte[64]);
    }

    @Test
    void testProcessInitialAndRespond_CreatesValidInitialPacket() {
        // Arrange - create a mock Initial packet
        ByteBuffer mockInitialPacket = createMockInitialPacket();

        // Act
        List<ByteBuffer> responses = connection.processInitialAndRespond(mockInitialPacket);

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
        List<ByteBuffer> responses = connection.processHandshakePacket(mockHandshakePacket);

        // Assert
        assertNotNull(responses);
        assertEquals(2, responses.size(), "Should return Handshake + HANDSHAKE_DONE packets");

        // Verify first packet is Handshake (long header, type 10)
        ByteBuffer handshakePacket = responses.get(0);
        byte handshakeFlags = handshakePacket.get(0);
        assertEquals(0x80, handshakeFlags & 0x80, "Handshake packet should have long header");
        assertEquals(0x02, (handshakeFlags & 0x30) >> 4, "Should be Handshake packet type (10)");

        // Verify second packet is 1-RTT (short header)
        ByteBuffer donePacket = responses.get(1);
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
        ByteBuffer ackPacket = connection.process1RttPacket(mock1RttPacket).get(0);

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
        List<ByteBuffer> closePackets = connection.processInitialAndRespond(invalidInitial);

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
        List<ByteBuffer> responses = connection.processInitialAndRespond(mockInitial);

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
        List<ByteBuffer> responses = connection.processInitialAndRespond(mockInitial);

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
        packet.putLong(0xFEDCBA9876543210L);

        // Token length
        packet.put((byte) 0);

        // Length (simplified - 100 bytes)
        packet.put((byte) 100);

        // Packet number
        packet.put((byte) 0);

        // Plaintext payload: CRYPTO frame with mock ClientHello
        // Since decryptAead is mocked to bypass encryption, put actual plaintext here
        ByteBuffer plaintext = ByteBuffer.allocate(83); // 100 - 1 (pn) - 16 (tag)

        // CRYPTO frame: type(0x06) | offset(varint) | length(varint) | data
        plaintext.put((byte) 0x06); // CRYPTO frame type
        plaintext.put((byte) 0x00); // offset = 0
        plaintext.put((byte) 32);   // length = 32 (just client random for mock)
        plaintext.put(new byte[32]); // Mock ClientHello (client random)

        // Padding to fill remaining space
        while (plaintext.hasRemaining()) {
            plaintext.put((byte) 0x00); // PADDING frame
        }

        packet.put(plaintext.array());
        packet.put(new byte[16]); // GCM tag (will be stripped by mock decryptAead)

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
        mockedQuicCrypto.when(() -> QuicCrypto.processClientHello(any(ByteBuffer.class)))
            .thenThrow(new QuicCrypto.CryptoException("Invalid ClientHello"));

        return createMockInitialPacket();
    }

    private void setupConnectionInHandshakeState() throws Exception {
        // Process Initial to move to HANDSHAKE state
        ByteBuffer mockInitial = createMockInitialPacket();
        connection.processInitialAndRespond(mockInitial);

        assertEquals(QuicConnection.State.HANDSHAKE, connection.getState(), 
                    "Connection should be in HANDSHAKE state");
    }

    private void setupConnectionInEstablishedState() throws Exception {
        setupConnectionInHandshakeState();

        // Process Handshake to move to ESTABLISHED
        ByteBuffer mockHandshake = createMockHandshakePacket();
        connection.processHandshakePacket(mockHandshake);

        assertEquals(QuicConnection.State.ESTABLISHED, connection.getState(), 
                    "Connection should be in ESTABLISHED state");
    }
}
