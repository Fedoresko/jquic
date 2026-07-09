package org.fmalyshev.quic;

import org.fmalyshev.quic.buffers.PoolBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

import static org.fmalyshev.quic.QuicCrypto.GCM_TAG_LENGTH;

/**
 * Builds complete QUIC packets with proper headers and encryption (RFC 9000 Section 17, RFC 9001 Section 5).
 * 
 * This builder encapsulates the correct QUIC packet construction process:
 * 1. Build packet header
 * 2. Encrypt payload with header as Associated Data (AEAD)
 * 3. Combine header + encrypted payload (with 16-byte GCM tag)
 * 
 * Per RFC 9001 Section 5.4.1, the AEAD function authenticates the packet header using Associated Data.
 * The GCM authentication tag protects BOTH the header and the encrypted payload.
 */
public class QuicPacketBuilder {
    // QUIC version 1 (RFC 9000)
    public static final int QUIC_VERSION_1 = 0x00000001;
    public static final int STATELESS_RESET_TOKEN_LENGTH = 16; // RFC 9000: 16 bytes
    private static final Logger log = LoggerFactory.getLogger(QuicPacketBuilder.class);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final byte[] ZERO_BLOCK = new byte[4096];
    private static final int MIN_STATELESS_RESET_LENGTH = 21; // 1 byte fixed bit + 4 bytes unpredictable + 16 bytes token

    /**
     * Builds Initial packet with long header and proper AEAD encryption (RFC 9000 Section 17.2.2, RFC 9001 Section 5).
     * 
     * This method correctly implements the QUIC packet protection:
     * 1. Constructs packet header
     * 2. Encrypts payload using AES-GCM with header as Associated Data
     * 3. Combines header + encrypted payload (which includes 16-byte GCM tag)
     * 
     * Format: flags(1) | version(4) | DCID_len(1) | DCID(8) | SCID_len(1) | SCID(8) | 
     *         token_len(varint) | length(varint) | packet_number(varint) | encrypted_payload(*)
     * 
     * @param destinationCid Destination connection ID
     * @param sourceCid Source connection ID
     * @param packetNumber Packet number
     * @param packetBuffer Plaintext payload (QUIC frames) to encrypt
     * @param keys Encryption keys (RFC 9001 Section 5.4)
     * @return Complete Initial packet ready to send
     * @throws QuicCrypto.CryptoException if encryption fails
     */
    public static PoolBuffer buildInitialPacket(byte [] destinationCid, ByteBuffer sourceCid,
                                                long packetNumber, ByteBuffer packetBuffer, QuicCrypto.PacketProtectionKeysWithHP keys) throws QuicCrypto.CryptoException {
        int encryptedPayloadSize = packetBuffer.remaining() + GCM_TAG_LENGTH;
        int pnLen = encodedPnLength(packetNumber);

        QuicPacketHeader header = new QuicPacketHeader(new QuicPacketHeader.PacketNumber(pnLen, packetNumber, (byte) 0),
                QUIC_VERSION_1, destinationCid, sourceCid.array(), QuicPacketHeader.PacketType.INITIAL,
                new byte[0], encryptedPayloadSize + pnLen, (byte)0
        );

        return encryptAndProtectQuicPacket(packetBuffer, keys.key(), keys.iv(), header, keys.headerProtection());
    }

    private static PoolBuffer encryptAndProtectQuicPacket(ByteBuffer plaintext, SecretKey key, byte[] iv, QuicPacketHeader header, byte[] hp_key) throws QuicCrypto.CryptoException {
        PoolBuffer packet = QuicEngine.getPool().requestWriteBuffer();
        int headerStart = packet.buf().position();
        header.write(packet.buf());
        ByteBuffer headerData = packet.buf().duplicate().position(headerStart).limit(packet.buf().position());
        int playloadStart = packet.buf().position();
        packet.buf().put(plaintext);
        ByteBuffer payloadData = packet.buf().duplicate().position(playloadStart).limit(packet.buf().position());
        QuicCrypto.encryptPacketInPlace(payloadData, key, header.packetNumber, headerData, iv);
        packet.buf().limit(payloadData.limit());
        packet.buf().position(headerStart);

        applyHeaderProtection(packet.buf(), header.headerLength, header.pnLength, hp_key);
        return packet;
    }

    /**
     * Builds Handshake packet with proper AEAD encryption (RFC 9000 Section 17.2.4, RFC 9001 Section 5).
     * 
     * @param destinationCid Destination connection ID
     * @param sourceCid Source connection ID
     * @param packetNumber Packet number
     * @param payload Plaintext payload (QUIC frames) to encrypt
     * @param keys Encryption keys (RFC 9001 Section 5.4)
     * @throws QuicCrypto.CryptoException if encryption fails
     */
    public static PoolBuffer buildHandshakePacket(byte [] destinationCid, ByteBuffer sourceCid,
                                                  long packetNumber, ByteBuffer payload, QuicCrypto.PacketProtectionKeysWithHP keys)
            throws QuicCrypto.CryptoException {
        int encryptedPayloadSize = payload.remaining() + GCM_TAG_LENGTH; // + GCM tag
        int pnLen = encodedPnLength(packetNumber);

        QuicPacketHeader header = new QuicPacketHeader(new QuicPacketHeader.PacketNumber(pnLen, packetNumber, (byte) 0),
            QUIC_VERSION_1, destinationCid, sourceCid.array(),
            QuicPacketHeader.PacketType.HANDSHAKE, new byte[0], encryptedPayloadSize + pnLen, (byte)0 );

        PoolBuffer byteBuffer = encryptAndProtectQuicPacket(payload, keys.key(), keys.iv(), header, keys.headerProtection());
        return byteBuffer;
    }

    /**
     * Builds 1-RTT packet with short header and proper AEAD encryption (RFC 9000 Section 17.3, RFC 9001 Section 5).
     * Format: flags(1) | DCID(8) | packet_number(1) | encrypted_payload(*)
     * 
     * @param destinationCid Destination connection ID
     * @param packetNumber Packet number
     * @param plaintext Plaintext payload (QUIC frames) to encrypt
     * @param keys Security keys (RFC 9001 Section 5.4)
     * @return Complete 1-RTT packet ready to send
     * @throws QuicCrypto.CryptoException if encryption fails
     */
    public static PoolBuffer build1RttPacket(byte [] destinationCid, long packetNumber,
                                             ByteBuffer plaintext, QuicCrypto.PacketProtectionKeys keys, byte [] hp_key, byte keyPhase) throws QuicCrypto.CryptoException {
        int pnLen = encodedPnLength(packetNumber);

        QuicPacketHeader header = new QuicPacketHeader(new QuicPacketHeader.PacketNumber(pnLen, packetNumber, (byte) 0),
                QUIC_VERSION_1, destinationCid, null,
                QuicPacketHeader.PacketType.ONE_RTT, null, -1, keyPhase);

        return encryptAndProtectQuicPacket(plaintext, keys.key(), keys.iv(), header, hp_key);
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
     * @param pnLen           packet number length in bytes (1–4)
     * @param hpKey           16-byte AES header protection key
     * @throws QuicCrypto.CryptoException if AES-ECB fails
     */
    private static void applyHeaderProtection(ByteBuffer packet, int headerLength, int pnLen,
                                              byte[] hpKey) throws QuicCrypto.CryptoException {
        if (hpKey == null || hpKey.length == 0) {
            return; // no-op for tests that pass a null/empty HP key
        }

        // RFC 9001 §5.4.2: sample_offset = pn_offset + 4
        // pn_offset is the start of the packet number field = headerLength - pnLen
        int sampleOffset = packet.position() + (headerLength - pnLen) + 4;
        if (packet.limit() < sampleOffset + 16) {
            throw new QuicCrypto.CryptoException(
                    "Packet too short to extract HP sample (limit=" + packet.limit() + ")");
        }

        byte[] sample = new byte[16];
        // packet is flipped (position=0, limit=total length), so absolute get is fine
        for (int i = 0; i < 16; i++) {
            sample[i] = packet.get(sampleOffset + i);
        }

        // Generate mask via AES-ECB
        byte[] mask;
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding", "Conscrypt");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
                    new javax.crypto.spec.SecretKeySpec(hpKey, "AES"));
            mask = cipher.doFinal(sample);
        } catch (java.security.GeneralSecurityException e) {
            throw new QuicCrypto.CryptoException("Header protection mask generation failed", e);
        }

        // XOR flags byte (index 0)
        boolean isLongHeader = (packet.get(packet.position()) & 0x80) != 0;
        byte maskedFlags = (byte) (packet.get(packet.position()) ^ (mask[0] & (isLongHeader ? 0x0F : 0x1F)));
        packet.put(packet.position(), maskedFlags);

        // XOR packet number bytes (last pnLen bytes of the header)
        int pnOffset = packet.position() + headerLength - pnLen;
        for (int i = 0; i < pnLen; i++) {
            packet.put(pnOffset + i, (byte) (packet.get(pnOffset + i) ^ mask[1 + i]));
        }
    }

    /**
     * Returns the minimum number of bytes (1–4) required to encode {@code packetNumber}
     * as a QUIC packet number field (RFC 9000 §17.1).
     */
    private static int encodedPnLength(long packetNumber) {
        if (packetNumber <= 0xFFL)       return 1;
        if (packetNumber <= 0xFFFFL)     return 2;
        if (packetNumber <= 0xFFFFFFL)   return 3;
        return 4;
    }

    static ByteBuffer writeStatelessResetFrame(long connectionId, int incomingPacketSize) {
        // RFC 9000: Stateless Reset should be smaller than incoming packet
        // to avoid amplification attacks, but at least 21 bytes
        int resetSize = Math.max(MIN_STATELESS_RESET_LENGTH,
                Math.min(incomingPacketSize - 1, 1200));

        ByteBuffer frameBuffer = ByteBuffer.allocate(resetSize);

        // First byte must have fixed bit (0x40) set to appear as valid short header
        byte firstByte = (byte) (0x40 | (SECURE_RANDOM.nextInt() & 0x3F));
        frameBuffer.put(firstByte);

        // Fill with random unpredictable bits (excluding last 16 bytes for token)
        int randomBytesCount = resetSize - 1 - STATELESS_RESET_TOKEN_LENGTH;
        byte[] randomBytes = new byte[randomBytesCount];
        SECURE_RANDOM.nextBytes(randomBytes);
        frameBuffer.put(randomBytes);

        // Add 16-byte Stateless Reset Token at the end
        // In a real implementation, this should be a pseudorandom function of the CID
        // For now, we use random bytes (stateless - doesn't require storing state)
        byte[] token = QuicCrypto.generateStatelessResetToken(ByteBuffer.allocate(8).putLong(connectionId).array());
        SECURE_RANDOM.nextBytes(token);
        frameBuffer.put(token);

        //Add required padding
        frameBuffer.put(ZERO_BLOCK, 0, resetSize - frameBuffer.position());

        frameBuffer.limit(frameBuffer.position());
        return frameBuffer.flip();
    }
}
