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
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.crypto.NativeCrypto;
import org.jquic.quic.crypto.QuicCrypto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

import static org.jquic.quic.crypto.QuicCrypto.GCM_TAG_LENGTH;

/**
 * Builds complete QUIC packets with proper headers and encryption (RFC 9000 Section 17, RFC 9001 Section 5).
 * This builder encapsulates the correct QUIC packet construction process:
 * 1. Build packet header
 * 2. Encrypt payload with header as Associated Data (AEAD)
 * 3. Combine header + encrypted payload (with 16-byte GCM tag)
 * Per RFC 9001 Section 5.4.1, the AEAD function authenticates the packet header using Associated Data.
 * The GCM authentication tag protects BOTH the header and the encrypted payload.
 */
public class QuicPacketBuilder {
    // QUIC version 1 (RFC 9000)
    public static final int STATELESS_RESET_TOKEN_LENGTH = 16; // RFC 9000: 16 bytes
    private static final Logger log = LoggerFactory.getLogger(QuicPacketBuilder.class);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int MIN_STATELESS_RESET_LENGTH = 21; // 1 byte fixed bit + 4 bytes unpredictable + 16 bytes token
    private static final ThreadLocal<ByteBuffer> sample = ThreadLocal.withInitial(()->ByteBuffer.allocateDirect(16));

    /**
     * Builds Initial packet with long header and proper AEAD encryption (RFC 9000 Section 17.2.2, RFC 9001 Section 5).
     * This method correctly implements the QUIC packet protection:
     * 1. Constructs packet header
     * 2. Encrypts payload using AES-GCM with header as Associated Data
     * 3. Combines header + encrypted payload (which includes 16-byte GCM tag)
     * Format: flags(1) | version(4) | DCID_len(1) | DCID(8) | SCID_len(1) | SCID(8) |
     *         token_len(varint) | length(varint) | packet_number(varint) | encrypted_payload(*)
     * 
     * @param destinationCid Destination connection ID
     * @param sourceCid Source connection ID
     * @param packetNumber Packet number
     * @param packetBuffer Plaintext payload (QUIC frames) to encrypt
     * @param crypto with encryption keys (RFC 9001 Section 5.4)
     * @return Complete Initial packet ready to send
     * @throws QuicCrypto.CryptoException if encryption fails
     */
    public static PoolBuffer buildInitialPacket(QuicVersion quicVersion, BufferPool bufferPool, byte [] destinationCid, ByteBuffer sourceCid,
                                                long packetNumber, long largestAcked, ByteBuffer packetBuffer, NativeCrypto crypto) throws QuicCrypto.CryptoException {
        int encryptedPayloadSize = packetBuffer.remaining() + GCM_TAG_LENGTH;
        int pnLen = QuicPacketHeader.calculatePnLength(packetNumber, largestAcked);

        QuicPacketHeader header = new QuicPacketHeader(new QuicPacketHeader.PacketNumber(pnLen, packetNumber, (byte) 0x10),
                quicVersion, destinationCid, sourceCid.array(), QuicPacketHeader.PacketType.INITIAL,
                new byte[0], encryptedPayloadSize + pnLen, (byte)0
        );

        return encryptAndProtectQuicPacket(bufferPool, packetBuffer, header, crypto);
    }

    private static PoolBuffer encryptAndProtectQuicPacket(BufferPool bufferPool, ByteBuffer plaintext, QuicPacketHeader header, NativeCrypto crypto) throws QuicCrypto.CryptoException {
        PoolBuffer packet = bufferPool.requestWriteBuffer();
        int headerStart = packet.buf().position();
        header.write(packet.buf());
        ByteBuffer headerData = packet.buf().duplicate().position(headerStart).limit(packet.buf().position());
        int playloadStart = packet.buf().position();
        packet.buf().put(plaintext);
        ByteBuffer payloadData = packet.buf().duplicate().position(playloadStart).limit(packet.buf().position());
        crypto.encryptPacketInPlace(payloadData, header.packetNumber, headerData);
        packet.buf().limit(payloadData.limit());
        packet.buf().position(headerStart);

        applyHeaderProtection(packet.buf(), header.headerLength, header.pnLength, crypto);
        return packet;
    }

    /**
     * Builds Handshake packet with proper AEAD encryption (RFC 9000 Section 17.2.4, RFC 9001 Section 5).
     * 
     * @param destinationCid Destination connection ID
     * @param sourceCid Source connection ID
     * @param packetNumber Packet number
     * @param payload Plaintext payload (QUIC frames) to encrypt
     * @param crypto with encryption keys (RFC 9001 Section 5.4)
     * @throws QuicCrypto.CryptoException if encryption fails
     */
    public static PoolBuffer buildHandshakePacket(QuicVersion quicVersion, BufferPool bufferPool, byte [] destinationCid, ByteBuffer sourceCid,
                                                  long packetNumber, long largestAcked, ByteBuffer payload, NativeCrypto crypto)
            throws QuicCrypto.CryptoException {
        int encryptedPayloadSize = payload.remaining() + GCM_TAG_LENGTH; // + GCM tag
        int pnLen = QuicPacketHeader.calculatePnLength(packetNumber, largestAcked);

        QuicPacketHeader header = new QuicPacketHeader(new QuicPacketHeader.PacketNumber(pnLen, packetNumber, (byte) 0x10),
            quicVersion, destinationCid, sourceCid.array(),
            QuicPacketHeader.PacketType.HANDSHAKE, new byte[0], encryptedPayloadSize + pnLen, (byte)0 );

        return encryptAndProtectQuicPacket(bufferPool, payload, header, crypto);
    }

    /**
     * Builds 1-RTT packet with short header and proper AEAD encryption (RFC 9000 Section 17.3, RFC 9001 Section 5).
     * Format: flags(1) | DCID(8) | packet_number(1) | encrypted_payload(*)
     * 
     * @param destinationCid Destination connection ID
     * @param packetNumber Packet number
     * @param largestAcked Largest acknowledged packet number
     * @param plaintext Plaintext payload (QUIC frames) to encrypt
     * @param crypto with encryption keys (RFC 9001 Section 5.4)
     * @return Complete 1-RTT packet ready to send
     * @throws QuicCrypto.CryptoException if encryption fails
     */
    public static PoolBuffer build1RttPacket(QuicVersion quicVersion, BufferPool bufferPool, byte [] destinationCid, long packetNumber, long largestAcked,
                                             ByteBuffer plaintext, NativeCrypto crypto, byte keyPhase) throws QuicCrypto.CryptoException {
        int pnLen = QuicPacketHeader.calculatePnLength(packetNumber, largestAcked);

        if (plaintext.hasRemaining() && plaintext.duplicate().get() == 0) {
            log.error("!!!!!!Very Strange packet");
        }

        QuicPacketHeader header = new QuicPacketHeader(new QuicPacketHeader.PacketNumber(pnLen, packetNumber, (byte) (0x40 | (keyPhase << 2))),
                quicVersion, destinationCid, null,
                QuicPacketHeader.PacketType.ONE_RTT, null, -1, keyPhase);

        return encryptAndProtectQuicPacket(bufferPool, plaintext, header, crypto);
    }

    /**
     * Applies RFC 9001 Section 5.4.1 header protection to an assembled packet in-place.
     *
     * <p>Sample = 16 bytes of ciphertext starting 4 bytes after the first ciphertext byte
     * (i.e. at offset {@code headerLength + 4} in the packet).
     * Mask = AES-ECB(headerProtectionKey, sample).
     * Then:
     * <ul>
     *   <li>Long header: flags XOR= mask[0] & 0x0F</li>
     *   <li>Short header: flags XOR= mask[0] & 0x1F</li>
     *   <li>Packet number bytes XOR= mask[1..pnLen]</li>
     * </ul>
     *
     * @param packet          fully assembled packet (flipped, ready to read)
     * @param headerLength    total header length in bytes (packet number is last {@code pnLen} bytes)
     * @param pnLen           packet number length in bytes (1-4)
     * @throws QuicCrypto.CryptoException if AES-ECB fails
     */
    private static void applyHeaderProtection(ByteBuffer packet, int headerLength, int pnLen,
                                              NativeCrypto crypto) throws QuicCrypto.CryptoException {
        if (crypto.getHpKey() == null) {
            return;
        }

        // RFC 9001 В§5.4.2: sample_offset = pn_offset + 4
        // pn_offset is the lower of the packet number field = headerLength - pnLen
        int sampleOffset = packet.position() + (headerLength - pnLen) + 4;

        if (packet.limit() < sampleOffset + 16) {
            throw new QuicCrypto.CryptoException(
                    "Packet too short to extract HP sample (limit=" + packet.limit() + ")");
        }

        sample.get().rewind().put(0, packet, sampleOffset, 16);

        // Generate mask using AES-ECB
        crypto.encryptEcbInPlace(sample.get());
        ByteBuffer mask = sample.get();

        // XOR flags byte (index 0)
        boolean isLongHeader = (packet.get(packet.position()) & 0x80) != 0;
        byte maskedFlags = (byte) (packet.get(packet.position()) ^ (mask.get(0) & (isLongHeader ? 0x0F : 0x1F)));
        packet.put(packet.position(), maskedFlags);

        // XOR packet number bytes (last pnLen bytes of the header)
        int pnOffset = packet.position() + headerLength - pnLen;
        for (int i = 0; i < pnLen; i++) {
            packet.put(pnOffset + i, (byte) (packet.get(pnOffset + i) ^ mask.get(1 + i)));
        }
    }

    public static PoolBuffer buildVersionNegotiationPacket(BufferPool bufferPool, byte[] destinationCid, byte[] sourceCid) {
        PoolBuffer packet = bufferPool.requestWriteBuffer();
        ByteBuffer buf = packet.buf();
        writeVersionNegotioationPaketToBuffer(destinationCid, sourceCid, buf);
        return packet;
    }

    public static void writeVersionNegotioationPaketToBuffer(byte[] destinationCid, byte[] sourceCid, ByteBuffer buf) {
        int start = buf.position();

        // Header Form (1) = 1, Unused (7) random
        byte firstByte = (byte) (0x80 | (SECURE_RANDOM.nextInt(0x80) & 0x7F));
        // Bit 1 MUST be set to 1 for fixed bit
        firstByte |= 0x40;
        buf.put(firstByte);

        // Version (32) = 0
        buf.putInt(0);

        // Destination Connection ID Length (8)
        buf.put((byte) destinationCid.length);
        buf.put(destinationCid);

        // Source Connection ID Length (8)
        buf.put((byte) sourceCid.length);
        buf.put(sourceCid);

        // Supported Version (32) - we only support V1 and V2
        buf.putInt(QuicVersion.QUIC_VERSION_1.val);
        buf.putInt(QuicVersion.QUIC_VERSION_2.val);

        buf.limit(buf.position());
        buf.position(start);
    }

    static PoolBuffer writeStatelessResetFrame(BufferPool bufferPool, int incomingPacketSize, byte[] statelessResetToken) {
        // RFC 9000: Stateless Reset should be smaller than incoming packet
        // to avoid amplification attacks, but at least 21 bytes
        int resetSize = Math.max(MIN_STATELESS_RESET_LENGTH,
                Math.min(incomingPacketSize - 1, 1200));

        PoolBuffer buffer = bufferPool.requestWriteBuffer();

        ByteBuffer frameBuffer = buffer.buf();

        int start = buffer.buf().position();

        // First byte must have fixed bit (0x40) set to appear as valid short header
        byte firstByte = (byte) (0x40 | (SECURE_RANDOM.nextInt() & 0x3F));
        frameBuffer.put(firstByte);

        // Randomize packet length a bit
        int minLen = Math.min(32, incomingPacketSize - 1);
        int maxLen = Math.min(64, incomingPacketSize - 1);
        int len = (maxLen == minLen) ? minLen : SECURE_RANDOM.nextInt(maxLen - minLen) + minLen;

        // Fill with random unpredictable bits (excluding last 16 bytes for token)
        int randomBytesCount = len - STATELESS_RESET_TOKEN_LENGTH;
        byte[] randomBytes = new byte[randomBytesCount];
        SECURE_RANDOM.nextBytes(randomBytes);
        frameBuffer.put(randomBytes);

        // Add 16-byte Stateless Reset Token at the higher
        // In a real implementation, this should be a pseudorandom function of the CID
        // For now, we use random bytes (stateless - doesn't require storing state)
        frameBuffer.put(statelessResetToken);

        frameBuffer.limit(frameBuffer.position());
        frameBuffer.position(start);
        return buffer;
    }
}

