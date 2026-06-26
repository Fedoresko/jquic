package org.fmalyshev.quic;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.fmalyshev.quic.QuicConnectionCryptoIntegrationTest.destinationCidBytes;
import static org.fmalyshev.quic.QuicCrypto.GCM_TAG_LENGTH;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for QuicPacketBuilder to verify RFC 9000 compliant packet headers.
 */
class QuicPacketBuilderTest {

    @Test
    void testBuildInitialPacket_HeaderStructure() throws QuicCrypto.CryptoException {
        // Arrange
        long destinationCid = 0x1234567890ABCDEFL;
        long sourceCid = 0xFEDCBA0987654321L;
        long packetNumber = 5;
        ByteBuffer payload = ByteBuffer.wrap(new byte[]{0x01, 0x02, 0x03, 0x04});
        int payloadSize = payload.remaining();

        // Act
        ByteBuffer packet = QuicPacketBuilder.buildInitialPacket(destinationCidBytes(destinationCid), sourceCid, packetNumber, payload, new QuicCrypto.PacketProtectionKeys(null,null,null));

        // Assert
        assertNotNull(packet);
        assertTrue(packet.hasRemaining(), "Packet should have data");

        // Verify header structure
        byte flags = packet.get();

        // Check long header bit (bit 7 = 1)
        assertEquals(0x80, flags & 0x80, "Long header bit should be set");

        // Check fixed bit (bit 6 = 1)
        assertEquals(0x40, flags & 0x40, "Fixed bit should be set");

        // Check packet type (bits 5-4 = 00 for Initial)
        assertEquals(0x00, (flags & 0x30) >> 4, "Packet type should be Initial (00)");

        // Check version
        int version = packet.getInt();
        assertEquals(0x00000001, version, "QUIC version should be 1");

        // Check DCID length
        byte dcidLen = packet.get();
        assertEquals(8, dcidLen, "DCID length should be 8");

        // Check DCID value
        long dcid = packet.getLong();
        assertEquals(destinationCid, dcid, "Destination CID should match");

        // Check SCID length
        byte scidLen = packet.get();
        assertEquals(8, scidLen, "SCID length should be 8");

        // Check SCID value
        long scid = packet.getLong();
        assertEquals(sourceCid, scid, "Source CID should match");

        // Check token length (should be 0 for server Initial)
        byte tokenLen = packet.get();
        assertEquals(0, tokenLen, "Token length should be 0 for server Initial");

        // Check length field (varint)
        long length = readVarint(packet);
        assertTrue(length > 0, "Length should be positive");

        // Check packet number
        byte pn = packet.get();
        assertEquals(packetNumber, pn & 0xFF, "Packet number should match");

        // Check encrypted payload is present (original payload + GCM tag)
        // When key is null, QuicCrypto returns plaintext + 16-byte tag
        assertEquals(payloadSize + GCM_TAG_LENGTH, packet.remaining(),
            "Remaining bytes should be encrypted payload (plaintext + GCM tag)");
    }

    @Test
    void testBuildHandshakePacket_HeaderStructure() throws QuicCrypto.CryptoException {
        // Arrange
        long destinationCid = 0xAAAABBBBCCCCDDDDL;
        long sourceCid = 0x1111222233334444L;
        long packetNumber = 10;
        ByteBuffer payload = ByteBuffer.wrap(new byte[100]);

        // Act
        ByteBuffer packet = QuicPacketBuilder.buildHandshakePacket(destinationCidBytes(destinationCid), sourceCid, packetNumber, payload, new QuicCrypto.PacketProtectionKeys(null, null, null));

        // Assert
        assertNotNull(packet);

        byte flags = packet.get();

        // Check long header bit (bit 7 = 1)
        assertEquals(0x80, flags & 0x80, "Long header bit should be set");

        // Check fixed bit (bit 6 = 1)
        assertEquals(0x40, flags & 0x40, "Fixed bit should be set");

        // Check packet type (bits 5-4 = 10 for Handshake)
        assertEquals(0x02, (flags & 0x30) >> 4, "Packet type should be Handshake (10)");

        // Check version
        int version = packet.getInt();
        assertEquals(0x00000001, version, "QUIC version should be 1");

        // Verify CIDs
        byte dcidLen = packet.get();
        assertEquals(8, dcidLen);
        long dcid = packet.getLong();
        assertEquals(destinationCid, dcid);

        byte scidLen = packet.get();
        assertEquals(8, scidLen);
        long scid = packet.getLong();
        assertEquals(sourceCid, scid);

        // Check length
        long length = readVarint(packet);
        assertTrue(length > 0, "Length should be positive");

        // Check packet number
        byte pn = packet.get();
        assertEquals(packetNumber, pn & 0xFF);
    }

    @Test
    void testBuild1RttPacket_ShortHeaderStructure() throws QuicCrypto.CryptoException {
        // Arrange
        long destinationCid = 0x9999888877776666L;
        long packetNumber = 42;
        ByteBuffer payload = ByteBuffer.wrap(new byte[]{(byte) 0xAA, (byte) 0xBB, (byte) 0xCC});
        int originalPayloadSize = payload.remaining();

        // Act
        ByteBuffer packet = QuicPacketBuilder.build1RttPacket(destinationCidBytes(destinationCid), packetNumber, payload, new QuicCrypto.PacketProtectionKeys(null, null, null), (byte) 0);

        // Assert
        assertNotNull(packet);

        byte flags = packet.get();

        // Check short header bit (bit 7 = 0)
        assertEquals(0x00, flags & 0x80, "Short header bit should NOT be set");

        // Check fixed bit (bit 6 = 1)
        assertEquals(0x40, flags & 0x40, "Fixed bit should be set");

        // Check DCID
        long dcid = packet.getLong();
        assertEquals(destinationCid, dcid, "Destination CID should match");

        // Check packet number
        byte pn = packet.get();
        assertEquals(packetNumber, pn & 0xFF, "Packet number should match");

        // Check encrypted payload is present (original payload + GCM tag)
        assertEquals(originalPayloadSize + GCM_TAG_LENGTH, packet.remaining(),
            "Remaining bytes should be encrypted payload (plaintext + GCM tag)");

        // Verify payload content (when key is null, plaintext is preserved before GCM tag)
        for (int i = 0; i < originalPayloadSize; i++) {
            assertEquals(payload.get(i), packet.get(), "Payload byte " + i + " should match");
        }

        // Remaining bytes should be GCM tag (16 bytes of zeros in mock mode)
        assertEquals(GCM_TAG_LENGTH, packet.remaining(), "Should have GCM tag remaining");
    }

    @Test
    void testBuildInitialPacket_PayloadIntegrity() throws QuicCrypto.CryptoException {
        // Arrange
        byte[] testData = new byte[256];
        for (int i = 0; i < testData.length; i++) {
            testData[i] = (byte) (i & 0xFF);
        }
        ByteBuffer payload = ByteBuffer.wrap(testData);

        // Act
        ByteBuffer packet = QuicPacketBuilder.buildInitialPacket(destinationCidBytes(0x1234L), 0x5678L, 0, payload, new QuicCrypto.PacketProtectionKeys(null, null, null));

        // Assert - skip header and verify payload
        skipInitialHeader(packet);

        for (int i = 0; i < testData.length; i++) {
            assertEquals(testData[i], packet.get(), "Payload byte " + i + " should be preserved");
        }
    }

    @Test
    void testBuild1RttPacket_MinimumSize() throws QuicCrypto.CryptoException {
        // Arrange
        ByteBuffer emptyPayload = ByteBuffer.allocate(0);

        // Act
        ByteBuffer packet = QuicPacketBuilder.build1RttPacket(destinationCidBytes(0x1234L), 0, emptyPayload, new QuicCrypto.PacketProtectionKeys(null, null, null), (byte) 0);

        // Assert - short header: 1 (flags) + 8 (CID) + 1 (PN) + 16 (GCM tag) = 26 bytes
        assertEquals(10 + GCM_TAG_LENGTH, packet.remaining(), 
            "Minimum 1-RTT packet should be header (10 bytes) + GCM tag (16 bytes)");
    }

    @Test
    void testBuildPackets_DifferentPacketNumbers() throws QuicCrypto.CryptoException {
        // Test that packet numbers are correctly encoded for different values
        for (int pn = 0; pn < 256; pn += 17) {
            ByteBuffer payload = ByteBuffer.wrap(new byte[10]);
            ByteBuffer packet = QuicPacketBuilder.build1RttPacket(destinationCidBytes(0x1234L), pn, payload, new QuicCrypto.PacketProtectionKeys(null, null, null), (byte) 0);

            packet.get(); // Skip flags
            packet.getLong(); // Skip CID

            byte encodedPn = packet.get();
            assertEquals(pn, encodedPn & 0xFF, "Packet number " + pn + " should be encoded correctly");

            // After PN, we should have encrypted payload (10 bytes) + GCM tag (16 bytes)
            assertEquals(10 + GCM_TAG_LENGTH, packet.remaining(), 
                "Should have encrypted payload + GCM tag remaining");
        }
    }

    @Test
    void testBuildInitialPacket_TokenLength() throws QuicCrypto.CryptoException {
        // Arrange
        ByteBuffer payload = ByteBuffer.wrap(new byte[50]);

        // Act
        ByteBuffer packet = QuicPacketBuilder.buildInitialPacket(destinationCidBytes(0x1111L), 0x2222L, 0, payload, new QuicCrypto.PacketProtectionKeys(null, null, null));

        // Assert - skip to token length field
        packet.position(1 + 4 + 1 + 8 + 1 + 8); // flags + version + dcid_len + dcid + scid_len + scid

        byte tokenLen = packet.get();
        assertEquals(0, tokenLen, "Server Initial should have token length = 0");
    }

    @Test
    void testBuildHandshakePacket_LengthField() throws QuicCrypto.CryptoException {
        // Arrange
        byte[] payloadData = new byte[200];
        ByteBuffer payload = ByteBuffer.wrap(payloadData);

        // Act
        ByteBuffer packet = QuicPacketBuilder.buildHandshakePacket(destinationCidBytes(0x1111L), 0x2222L, 5, payload, new QuicCrypto.PacketProtectionKeys(null, null, null));

        // Assert - skip to length field
        packet.position(1 + 4 + 1 + 8 + 1 + 8); // flags + version + dcid_len + dcid + scid_len + scid

        long length = readVarint(packet);
        // Length should include payload + packet number (1 byte)
        assertEquals(payloadData.length + GCM_TAG_LENGTH + 1, length, "Length field should include payload + packet number");
    }

    // Helper methods

    private void skipInitialHeader(ByteBuffer packet) {
        packet.get(); // flags
        packet.getInt(); // version
        packet.get(); // dcid_len
        packet.getLong(); // dcid
        packet.get(); // scid_len
        packet.getLong(); // scid
        packet.get(); // token_len
        readVarint(packet); // length
        packet.get(); // packet_number
    }

    private long readVarint(ByteBuffer buffer) {
        if (!buffer.hasRemaining()) return 0;

        byte first = buffer.get();
        int prefix = (first & 0xC0) >> 6;

        switch (prefix) {
            case 0: 
                return first & 0x3F;
            case 1: 
                return ((first & 0x3F) << 8) | (buffer.get() & 0xFF);
            case 2: 
                return ((first & 0x3F) << 24) | 
                       ((buffer.get() & 0xFF) << 16) |
                       ((buffer.get() & 0xFF) << 8) | 
                       (buffer.get() & 0xFF);
            case 3:
                long value = (first & 0x3F);
                for (int i = 0; i < 7; i++) {
                    value = (value << 8) | (buffer.get() & 0xFF);
                }
                return value;
            default: 
                return 0;
        }
    }
}
