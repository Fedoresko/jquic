package org.fmalyshev.quic;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.HexFormat;

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
    private static final Logger log = LoggerFactory.getLogger(QuicPacketBuilder.class);

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
     * @param plaintext Plaintext payload (QUIC frames) to encrypt
     * @param keys Encryption keys (RFC 9001 Section 5.4)
     * @return Complete Initial packet ready to send
     * @throws QuicCrypto.CryptoException if encryption fails
     */
    public static ByteBuffer buildInitialPacket(byte [] destinationCid, long sourceCid,
                                                long packetNumber, ByteBuffer plaintext, QuicCrypto.PacketProtectionKeys keys) throws QuicCrypto.CryptoException {

        int encryptedPayloadSize = plaintext.remaining() + GCM_TAG_LENGTH;
        int pnLen = encodedPnLength(packetNumber);

        byte [] scid = ByteBuffer.allocate(8).putLong(sourceCid).flip().array();
        
        QuicPacketHeader header = new QuicPacketHeader(new QuicPacketHeader.PacketNumber(pnLen, packetNumber, (byte) 0),
                QUIC_VERSION_1, destinationCid, scid, QuicPacketHeader.PacketType.INITIAL,
                new byte[0], encryptedPayloadSize + pnLen, (byte) 0
        );

        return encryptAndProtectQuicPacket(plaintext, keys, header);
    }

    private static ByteBuffer encryptAndProtectQuicPacket(ByteBuffer plaintext, QuicCrypto.PacketProtectionKeys keys, QuicPacketHeader header) throws QuicCrypto.CryptoException {
        ByteBuffer encryptedPayload = QuicCrypto.encryptPacket(plaintext, keys.key, header.packetNumber, header.rawData, keys.iv);

        ByteBuffer packet = ByteBuffer.allocate(header.headerLength + encryptedPayload.remaining());
        packet.put(header.rawData);
        packet.put(encryptedPayload);
        packet.flip();

        applyHeaderProtection(packet, header.headerLength, header.pnLength, keys.headerProtection);
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
     * @return Complete Handshake packet ready to send
     * @throws QuicCrypto.CryptoException if encryption fails
     */
    public static ByteBuffer buildHandshakePacket(byte [] destinationCid, long sourceCid,
                                                  long packetNumber, ByteBuffer payload, QuicCrypto.PacketProtectionKeys keys)
            throws QuicCrypto.CryptoException {
        int encryptedPayloadSize = payload.remaining() + GCM_TAG_LENGTH; // + GCM tag
        int pnLen = encodedPnLength(packetNumber);

        QuicPacketHeader header = new QuicPacketHeader(new QuicPacketHeader.PacketNumber(pnLen, packetNumber, (byte) 0),
            QUIC_VERSION_1, destinationCid, ByteBuffer.allocate(8).putLong(sourceCid).array(),
            QuicPacketHeader.PacketType.HANDSHAKE, new byte[0], encryptedPayloadSize + pnLen, (byte) 0);

        ByteBuffer byteBuffer = encryptAndProtectQuicPacket(payload, keys, header);
        log.info("ADD: {}", HexFormat.of().formatHex(header.rawData));
        log.info("ENCRYPTED: {}", HexFormat.of().formatHex(byteBuffer.array()));
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
    public static ByteBuffer build1RttPacket(byte [] destinationCid, long packetNumber,
                                             ByteBuffer plaintext, QuicCrypto.PacketProtectionKeys keys, byte keyPhase) throws QuicCrypto.CryptoException {
        int pnLen = encodedPnLength(packetNumber);

        QuicPacketHeader header = new QuicPacketHeader(new QuicPacketHeader.PacketNumber(pnLen, packetNumber, (byte) 0),
                QUIC_VERSION_1, destinationCid, null,
                QuicPacketHeader.PacketType.ONE_RTT, null, -1, keyPhase);

        return encryptAndProtectQuicPacket(plaintext, keys, header);
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
        int sampleOffset = (headerLength - pnLen) + 4;
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
        boolean isLongHeader = (packet.get(0) & 0x80) != 0;
        byte maskedFlags = (byte) (packet.get(0) ^ (mask[0] & (isLongHeader ? 0x0F : 0x1F)));
        packet.put(0, maskedFlags);

        // XOR packet number bytes (last pnLen bytes of the header)
        int pnOffset = headerLength - pnLen;
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
}
