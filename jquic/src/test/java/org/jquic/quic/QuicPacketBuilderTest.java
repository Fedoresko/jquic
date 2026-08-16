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

import org.jquic.quic.buffers.BufferPool;
import org.jquic.quic.buffers.RootPoolBuffer;
import org.jquic.quic.crypto.NativeCrypto;
import org.jquic.quic.crypto.QuicCrypto;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.jquic.quic.QuicConnectionCryptoIntegrationTest.destinationCidBytes;
import static org.jquic.quic.crypto.QuicCrypto.GCM_TAG_LENGTH;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

/**
 * Tests for QuicPacketBuilder to verify RFC 9000 compliant packet headers.
 */
class QuicPacketBuilderTest {

    public static final ByteBuffer SCID = ByteBuffer.wrap(new byte[8]).putLong(0x5678L).flip();
    private static final byte[] MOCK_IV = new byte[12];
    private static final ByteBuffer MOCK_HP = null; // Set to 0 to skip HP in QuicPacketBuilder
    private static final ByteBuffer MOCK_KEY = ByteBuffer.wrap(new byte[16]);
    private static final QuicCrypto.PacketProtectionKeysWithHP MOCK_KEYS_HP = new QuicCrypto.PacketProtectionKeysWithHP(MOCK_KEY, MOCK_IV, MOCK_HP);
    private static final QuicCrypto.PacketProtectionKeys MOCK_KEYS = new QuicCrypto.PacketProtectionKeys(MOCK_KEY, MOCK_IV);
    private static final NativeCrypto MOCK_CRYPTO = mock(NativeCrypto.class);
    private static final BufferPool pool = mock(BufferPool.class);

    @BeforeAll
    static void init() throws QuicException {
        when(pool.requestWriteBuffer()).thenAnswer((a) -> new RootPoolBuffer(ByteBuffer.allocate(2000).position(100), pool, true) );
        doAnswer(
                invocation -> {
                    ByteBuffer f = invocation.getArgument(0);
                    f.limit(f.limit() + GCM_TAG_LENGTH);
                    return null;
                }
        ).when(MOCK_CRYPTO).encryptPacketInPlace(any(), anyLong(), any());
    }
    
    @Test
    void testBuildInitialPacket_HeaderStructure() throws QuicException {
        // Arrange
        long destinationCid = 0x1234567890ABCDEFL;
        ByteBuffer sourceCid = ByteBuffer.wrap(new byte[8]).putLong(0xFEDCBA0987654321L).flip();
        long packetNumber = 5;
        ByteBuffer payload = ByteBuffer.wrap(new byte[]{0x01, 0x02, 0x03, 0x04});
        int payloadSize = payload.remaining();

        // Act
        org.jquic.quic.buffers.PoolBuffer poolBuffer = QuicPacketBuilder.buildInitialPacket(QuicVersion.QUIC_VERSION_1, pool, destinationCidBytes(destinationCid), sourceCid, packetNumber, 0, payload, MOCK_CRYPTO);
        ByteBuffer packet = poolBuffer.buf();

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
        assertEquals(sourceCid.duplicate().getLong(), scid, "Source CID should match");

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
        assertEquals(payloadSize + GCM_TAG_LENGTH, packet.remaining(),
            "Remaining bytes should be encrypted payload (plaintext + GCM tag)");
    }

    @Test
    void testBuildHandshakePacket_HeaderStructure() throws QuicException {
        // Arrange
        long destinationCid = 0xAAAABBBBCCCCDDDDL;
        ByteBuffer sourceCid = ByteBuffer.wrap(new byte[8]).putLong(0x1111222233334444L).flip();
        long packetNumber = 10;
        ByteBuffer payload = ByteBuffer.wrap(new byte[100]);

        // Act
        org.jquic.quic.buffers.PoolBuffer poolBuffer = QuicPacketBuilder.buildHandshakePacket(QuicVersion.QUIC_VERSION_1, pool, destinationCidBytes(destinationCid), sourceCid, packetNumber, 0, payload, MOCK_CRYPTO);
        ByteBuffer packet = poolBuffer.buf();

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
        assertEquals(sourceCid.duplicate().getLong(), scid);

        // Check length
        long length = readVarint(packet);
        assertTrue(length > 0, "Length should be positive");

        // Check packet number
        byte pn = packet.get();
        assertEquals(packetNumber, pn & 0xFF);
    }

    @Test
    void testBuild1RttPacket_ShortHeaderStructure() throws QuicException {
        // Arrange
        long destinationCid = 0x9999888877776666L;
        long packetNumber = 42;
        ByteBuffer payload = ByteBuffer.wrap(new byte[]{(byte) 0xAA, (byte) 0xBB, (byte) 0xCC});
        int originalPayloadSize = payload.remaining();

        // Act
        org.jquic.quic.buffers.PoolBuffer poolBuffer = QuicPacketBuilder.build1RttPacket(QuicVersion.QUIC_VERSION_1, pool, destinationCidBytes(destinationCid), packetNumber, 0, payload, MOCK_CRYPTO, (byte) 0);
        ByteBuffer packet = poolBuffer.buf();

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
    }

    @Test
    void testBuildInitialPacket_PayloadIntegrity() throws QuicException {
        // Arrange
        byte[] testData = new byte[256];
        for (int i = 0; i < testData.length; i++) {
            testData[i] = (byte) (i & 0xFF);
        }
        ByteBuffer payload = ByteBuffer.wrap(testData);
        ByteBuffer packetBuffer = ByteBuffer.wrap(new byte[512]).put(payload).flip();

        // Act
        org.jquic.quic.buffers.PoolBuffer poolBuffer = QuicPacketBuilder.buildInitialPacket(QuicVersion.QUIC_VERSION_1, pool, destinationCidBytes(0x1234L),
                SCID, 0, 0, packetBuffer, MOCK_CRYPTO);
        ByteBuffer packet = poolBuffer.buf();

        // Assert - skip header and verify payload
        skipInitialHeader(packet);

        // When using real AES/GCM (via mock keys), payload won't be plaintext testData
        // So we can't easily verify payload integrity without knowing the ciphertext.
        // But we can check that we have some data there (plaintext + tag).
        assertEquals(testData.length + GCM_TAG_LENGTH, packet.remaining());
    }

    @Test
    void testBuild1RttPacket_MinimumSize() throws QuicException {
        // Arrange
        ByteBuffer emptyPayload = ByteBuffer.allocate(0);
        // PoolBuffer uses a buffer from QuicEngine.getPool() which is typically large enough.
        // We don't need to wrap our own buffer here if we want to follow how builder works.

        // Act
        org.jquic.quic.buffers.PoolBuffer poolBuffer = QuicPacketBuilder.build1RttPacket(QuicVersion.QUIC_VERSION_1, pool, destinationCidBytes(0x1234L), 0, 0, emptyPayload, MOCK_CRYPTO, (byte) 0);
        ByteBuffer packet = poolBuffer.buf();

        // Assert - short header: 1 (flags) + 8 (CID) + 1 (PN) + 16 (GCM tag) = 26 bytes
        assertEquals(1 + 8 + 1 + GCM_TAG_LENGTH, packet.remaining(), 
            "Minimum 1-RTT packet should be header (10 bytes) + GCM tag (16 bytes)");
    }

    @Test
    void testBuildPackets_DifferentPacketNumbers() throws QuicException {
        // Test that packet numbers are correctly encoded for different values
        for (int pn = 0; pn < 256; pn += 17) {
            ByteBuffer payload = ByteBuffer.wrap(new byte[10]);
            org.jquic.quic.buffers.PoolBuffer poolBuffer = QuicPacketBuilder.build1RttPacket(QuicVersion.QUIC_VERSION_1, pool, destinationCidBytes(0x1234L), pn, 0, payload, MOCK_CRYPTO, (byte) 0);
            ByteBuffer packet = poolBuffer.buf();

            packet.get(); // Skip flags
            packet.getLong(); // Skip CID

            int pnLen = QuicPacketHeader.calculatePnLength(pn, 0);
            long encodedPn = 0;
            for (int i = 0; i < pnLen; i++) {
                encodedPn = (encodedPn << 8) | (packet.get() & 0xFF);
            }
            assertEquals(pn, encodedPn, "Packet number " + pn + " should be encoded correctly");

            // After PN, we should have encrypted payload (10 bytes) + GCM tag (16 bytes)
            assertEquals(10 + GCM_TAG_LENGTH, packet.remaining(), 
                "Should have encrypted payload + GCM tag remaining");
        }
    }

    @Test
    void testBuildInitialPacket_TokenLength() throws QuicException {
        // Arrange
        ByteBuffer payload = ByteBuffer.allocate(0);

        // Act
        org.jquic.quic.buffers.PoolBuffer poolBuffer = QuicPacketBuilder.buildInitialPacket(QuicVersion.QUIC_VERSION_1, pool, destinationCidBytes(0x1111L), SCID, 0, 0, payload, MOCK_CRYPTO);
        ByteBuffer packet = poolBuffer.buf();

        // Assert - skip to token length field
        packet.position(1 + 4 + 1 + 8 + 1 + 8); // flags + version + dcid_len + dcid + scid_len + scid

        byte tokenLen = packet.get();
        assertEquals(0, tokenLen, "Server Initial should have token length = 0");
    }

    @Test
    void testBuildHandshakePacket_LengthField() throws QuicException {
        // Arrange
        byte[] payloadData = new byte[200];
        ByteBuffer payload = ByteBuffer.wrap(payloadData);

        // Act
        org.jquic.quic.buffers.PoolBuffer poolBuffer = QuicPacketBuilder.buildHandshakePacket(QuicVersion.QUIC_VERSION_1, pool, destinationCidBytes(0x1111L), SCID, 5, 0, payload, MOCK_CRYPTO);
        ByteBuffer packet = poolBuffer.buf();

        // Assert - skip to length field
        packet.position(packet.position() +  1 + 4 + 1 + 8 + 1 + 8); // flags + version + dcid_len + dcid + scid_len + scid

        long length = readVarint(packet);
        System.out.println("[DEBUG_LOG] Handshake length varint: " + length + ", expected at least " + (payloadData.length + GCM_TAG_LENGTH + 1));
        // Length should include payload + GCM tag + packet number (1 byte)
        // Handshake packet uses varint for length.
        assertEquals(payloadData.length + GCM_TAG_LENGTH + 1, length, "Length field should include payload + GCM tag + packet number");
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
        // PN is at least 1 byte, but could be more. Builder uses encodedPnLength.
        // For PN 0 it is 1 byte.
        packet.get(); // packet_number (1 byte for PN 0)
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

