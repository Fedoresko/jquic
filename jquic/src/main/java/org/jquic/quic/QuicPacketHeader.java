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

import org.jquic.quic.crypto.NativeCrypto;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * Represents a QUIC packet header with header protection still applied.
 * The packet number and lower bits of the flags byte are still masked.
 * Call unmask() to remove protection and get a proper QuicPacketHeader.
 */
public class QuicPacketHeader {
    private static final Logger log = LoggerFactory.getLogger(QuicPacketHeader.class);
    private static final ThreadLocal<ByteBuffer> sample = ThreadLocal.withInitial(()->ByteBuffer.allocateDirect(16));

    public final Long packetNumber;
    public final int pnLength;
    public final int version;
    public final byte[] destinationCid;
    public final byte[] sourceCid;
    public final PacketType packetType;
    public final byte[] token;
    public final long payloadLength;
    public final int headerLength;
    public final byte flags;
    public final ByteBuffer rawData;

    public QuicPacketHeader(PacketNumber packetNumber,
                            QuicVersion quicVersion, byte[] destinationCid,
                            byte[] sourceCid, PacketType packetType, byte[] token, long payloadLength, byte keyPhase) {
        this(packetNumber, quicVersion, destinationCid, sourceCid, packetType, token, payloadLength, keyPhase, null);
    }

    public QuicPacketHeader(PacketNumber packetNumber,
                            QuicVersion quicVersion, byte[] destinationCid,
                            byte[] sourceCid, PacketType packetType, byte[] token, long payloadLength, byte keyPhase, ByteBuffer rawData) {

        flags = packetType.isLongHeader() ?
                buildLongHeaderFlags(quicVersion, packetType, packetNumber.pnLength) :
                buildShortHeaderFlags((byte)0, keyPhase, packetNumber.pnLength);

        this.packetNumber = packetNumber.packetNumber;
        this.pnLength = packetNumber.pnLength;
        this.packetType = packetType;
        this.version = quicVersion.val;
        this.destinationCid = destinationCid;
        this.sourceCid = sourceCid;
        this.token = token;
        this.payloadLength = payloadLength;
        this.headerLength = (rawData == null) ? measureHeaderLength() : rawData.remaining();
        this.rawData = rawData;
    }

    private int measureHeaderLength() {
        int headerLength = 1;
        if (packetType.isLongHeader()) {
            headerLength+=6;
            headerLength+= destinationCid.length;
            headerLength+= sourceCid.length;
            if (packetType == PacketType.INITIAL) {
                headerLength+=1;
                headerLength+= token.length;
            }
            headerLength+=QuicVarint.sizeOf(this.payloadLength);
            headerLength+=pnLength;
        } else {
            headerLength+= destinationCid.length;
            headerLength+=pnLength;
        }
        return headerLength;
    }

    private static void writePacketNumber(ByteBuffer buf, long pn, int pnLen) {
        for (int i = pnLen - 1; i >= 0; i--) {
            buf.put((byte) (pn >> (i * 8)));
        }
    }

    /**
     * RFC 9000 Appendix A.2. Packet Number Encoding
     * Calculates the minimum length (1-4) required to encode the packet number.
     */
    public static int calculatePnLength(long packetNumber, long largestAcked) {
        long delta = packetNumber - largestAcked;
        // RFC 9000: The number of bits required to represent 2 * delta
        // If delta is huge, we might need more than 4 bytes, but QUIC only supports up to 4.
        long delta2 = delta * 2;
        if (delta2 >= 0 && delta2 <= (1L << 8)) return 1;
        if (delta2 >= 0 && delta2 <= (1L << 16)) return 2;
        if (delta2 >= 0 && delta2 <= (1L << 24)) return 3;
        return 4;
    }

    /**
     * RFC 9000 Appendix A.2. Packet Number Encoding
     * Truncates the packet number to the specified length.
     */
    public static long truncatePacketNumber(long packetNumber, int pnLen) {
        long mask = (1L << (pnLen * 8)) - 1;
        if (pnLen == 8) mask = -1L;
        return packetNumber & mask;
    }

    public void write(ByteBuffer header) {
        byte unmaskedFlags = (byte) (flags | (pnLength - 1));
        header.put(unmaskedFlags);
        long truncatedPn = truncatePacketNumber(packetNumber, pnLength);
        if (packetType.isLongHeader()) {
            // Version
            header.putInt(version);

            header.put((byte) destinationCid.length);
            header.put(destinationCid);

            // Source CID length (8 bytes)
            header.put((byte) sourceCid.length);
            header.put(sourceCid);

            // Token length (0 for server Initial)
            if (packetType == PacketType.INITIAL) {
                QuicVarint.write(header, token.length);
                header.put(token);
            }

            // Length = encrypted payload size + packet number bytes
            QuicVarint.write(header, this.payloadLength);

            // Packet number (pnLen bytes, big-endian)
            writePacketNumber(header, truncatedPn, pnLength);
        } else {
            if (destinationCid.length > 0) {
                header.put(destinationCid);
            }

            // Packet number (pnLen bytes, big-endian)
            writePacketNumber(header, truncatedPn, pnLength);
        }
    }

    /**
     * Parses a QUIC packet header, reading even the protected packet number bytes.
     * Returns a masked header that needs unmask() to be called.
     * Returns null if the packet is malformed (RFC 9000: silently discard).
     */
    public static QuicPacketHeader parse(ByteBuffer packet, @Nullable NativeCrypto crypto, long largestPn) {
        try {
            int startPosition = packet.position();

            // Read flags byte (still protected in lower bits)
            byte flags = packet.get();
            boolean isLongHeader = (flags & 0x80) != 0;

            if (isLongHeader) {
                return parseLongHeader(packet, startPosition, flags, crypto, largestPn);
            } else {
                return parseShortHeader(packet, startPosition, flags, crypto, largestPn);
            }
        } catch (Exception e) {
            // RFC 9000: Silently discard malformed packets
            return null;
        }
    }

    public static PacketSummary parseSummary(ByteBuffer packet) {
        try {
            int pos = packet.position();
            byte flags = packet.get();

            if ((flags & 0x40) == 0) {
                log.info("Not valid QUIC packet");
                return null; //not valid QIUC packet
            }

            if ((flags & 0x80) == 0) {
                byte[] destinationCid = new byte[8];
                packet.get(destinationCid);

                packet.position(pos);
                return new PacketSummary(PacketType.ONE_RTT, QuicVersion.UNKNOWN, destinationCid, null); // Not long header
            }

            QuicVersion version = QuicVersion.of(packet.getInt());

            // Read DCID
            int dcidLen = packet.get() & 0xFF;
            byte[] destinationCid = new byte[dcidLen];
            packet.get(destinationCid);

            // Read SCID
            int scidLen = packet.get() & 0xFF;
            byte[] sourceCid = new byte[scidLen];
            packet.get(sourceCid);

            packet.position(pos);
            return new PacketSummary(fromFlags(version, flags), version, destinationCid, sourceCid);
        } catch (Exception e) {
            return null;
        }
    }

    public record PacketSummary(PacketType type, QuicVersion version, byte[] dcid, byte[] scid) {}

    private static PacketType fromFlags(QuicVersion quicVersion, byte flags) {
        int typeField = (flags & 0x30) >> 4;
        if (quicVersion == QuicVersion.QUIC_VERSION_2) {
            return switch (typeField) {
                case 0x01 -> PacketType.INITIAL;
                case 0x02 -> PacketType.ZERO_RTT;
                case 0x03 -> PacketType.HANDSHAKE;
                case 0x00 -> PacketType.RETRY;
                default -> null;
            };
        } else {
            return switch (typeField) {
                case 0x00 -> PacketType.INITIAL;
                case 0x01 -> PacketType.ZERO_RTT;
                case 0x02 -> PacketType.HANDSHAKE;
                case 0x03 -> PacketType.RETRY;
                default -> null;
            };
        }
    }

    private static QuicPacketHeader parseLongHeader(ByteBuffer packet, int startPosition, byte flags, NativeCrypto crypto, long largestPn) {
        // Read version (4 bytes)
        QuicVersion version = QuicVersion.of(packet.getInt());

        // Read DCID
        int dcidLen = packet.get() & 0xFF;
        byte[] destinationCid = new byte[dcidLen];
        packet.get(destinationCid);

        // Read SCID
        int scidLen = packet.get() & 0xFF;
        byte[] sourceCid = new byte[scidLen];
        packet.get(sourceCid);

        // Determine packet type from flags
        PacketType packetType = fromFlags(version, flags);
        byte[] token;
        if (Objects.requireNonNull(packetType) == PacketType.INITIAL) {// Read token
            long tokenLen = QuicVarint.read(packet);
            token = new byte[(int) tokenLen];
            packet.get(token);
        } else {
            token = null;
        }

        // Read payload length (varint)
        long payloadLength = QuicVarint.read(packet);
        PacketNumber packetNumber = readPacketNumber(packet, true, flags, startPosition, crypto, largestPn);

        int hederEnd = packet.position();
        ByteBuffer rawData = packet.duplicate().position(startPosition).limit(hederEnd);
        return new QuicPacketHeader(packetNumber, version, destinationCid, sourceCid,
                                         packetType, token, payloadLength, (byte) 0, rawData);
    }

    private static QuicPacketHeader parseShortHeader(ByteBuffer packet, int startPosition, byte flags, NativeCrypto crypto, long largestPn) {
        // Short header has DCID but no length field (must know from connection context)
        // For now, assume 8-byte DCID
        byte[] destinationCid = new byte[8];
        packet.get(destinationCid);

        PacketNumber packetNumber = readPacketNumber(packet, false, flags, startPosition, crypto, largestPn);

        int hederEnd = packet.position();
        ByteBuffer rawData = packet.duplicate().position(startPosition).limit(hederEnd);

        return new QuicPacketHeader(packetNumber, QuicVersion.UNKNOWN, destinationCid, null, PacketType.ONE_RTT, null, -1, (byte) (packetNumber.flags >> 2 & 0x01), rawData);
    }

    public record PacketNumber(int pnLength, long packetNumber, byte flags) {}

    public static PacketNumber readPacketNumber(ByteBuffer packet, boolean isLongHeader, byte protectedFlags, int startPosition, @Nullable NativeCrypto crypto, long largestPn) {
        if (crypto == null || crypto.getHpKey() == null) {
            int pnLength = getPacketNumberLength(protectedFlags);
            long truncatedPn = readPacketNumber(packet, pnLength);
            long fullPn = decodePacketNumber(largestPn, truncatedPn, pnLength * 8);
            return new PacketNumber(pnLength, fullPn, protectedFlags);
        } else {
            return readPacketNumberMasked(packet, isLongHeader, protectedFlags, startPosition, crypto, largestPn);
        }
    }

    /**
     * Removes header protection and returns a proper QuicPacketHeader.
     *
     * @return Unmasked QuicPacketHeader with correct packet number, or null if unmasking fails
     */
    public static PacketNumber readPacketNumberMasked(ByteBuffer packet, boolean isLongHeader, byte protectedFlags, int startPosition, @NonNull NativeCrypto crypto, long largestPn) {

        try {
            // Sample starts 4 bytes after packet number starts
            int sampleOffset = 4;

            sample.get().rewind().put(0, packet, packet.position() + sampleOffset, 16);

            // Generate mask using AES-ECB
            crypto.encryptEcbInPlace(sample.get());
            ByteBuffer mask = sample.get();

            // Unmask the flags byte
            byte unmaskedFlags = protectedFlags;
            if (isLongHeader) {
                unmaskedFlags ^= (byte) (mask.get(0) & 0x0F); // Unmask lower 4 bits
            } else {
                unmaskedFlags ^= (byte) (mask.get(0) & 0x1F); // Unmask lower 5 bits
            }

            packet.duplicate().position(startPosition).put(unmaskedFlags);

            // Get actual packet number length from unmasked flags
            int pnLength = (unmaskedFlags & 0x03) + 1;

            // Unmask packet number bytes
            long truncatedPn = 0;
            for (int i = 0; i < pnLength; i++) {
                byte protectedByte = packet.get();
                byte unmaskedByte = (byte) (protectedByte ^ mask.get(1 + i));
                packet.position(packet.position()-1).put(unmaskedByte);
                truncatedPn = (truncatedPn << 8) | (unmaskedByte & 0xFF);
            }

            long fullPn = decodePacketNumber(largestPn, truncatedPn, pnLength * 8);

            return new PacketNumber(pnLength, fullPn, unmaskedFlags);
        } catch (Exception e) {
            // RFC 9000: Silently discard malformed packets
            return null;
        }
    }

    /**
     * RFC 9000 Appendix A. Packet Number Decoding
     */
    public static long decodePacketNumber(long largestPn, long truncatedPn, int pnNbits) {
        long expectedPn = largestPn + 1;
        long pnWin = 1L << pnNbits;
        long pnHalfWin = pnWin / 2;
        long pnMask = pnWin - 1;

        if (pnNbits == 64) pnMask = -1L;

        long candidatePn = (expectedPn & ~pnMask) | truncatedPn;

        if (candidatePn <= expectedPn - pnHalfWin && candidatePn < (1L << 62) - pnWin) {
            return candidatePn + pnWin;
        } else if (candidatePn > expectedPn + pnHalfWin && candidatePn >= pnWin) {
            return candidatePn - pnWin;
        } else {
            return candidatePn;
        }
    }

    /**
     * Extracts packet number length from flags byte.
     * Bits 0-1 encode (length - 1), so possible values are 1-4 bytes.
     */
    private static int getPacketNumberLength(byte flags) {
        return (flags & 0x03) + 1;
    }

    /**
     * Reads a packet number of the specified length (1-4 bytes).
     */
    private static long readPacketNumber(ByteBuffer buffer, int length) {
        // RFC 9000: Malformed packet - will be caught by try-catch in parse()
        return switch (length) {
            case 1 -> buffer.get() & 0xFF;
            case 2 -> buffer.getShort() & 0xFFFF;
            case 3 -> ((buffer.get() & 0xFF) << 16) | (buffer.getShort() & 0xFFFF);
            case 4 -> buffer.getInt() & 0xFFFFFFFFL;
            default -> throw new IllegalArgumentException("Invalid packet number length: " + length);
        };
    }

    public enum PacketType {
        INITIAL,
        ZERO_RTT,
        HANDSHAKE,
        RETRY,
        ONE_RTT;

        public boolean isLongHeader() {
            return this != ONE_RTT;
        }
    }

    private static byte buildLongHeaderFlags(QuicVersion version, PacketType packetType, int pnLength) {
        // Bit 0: Header Form must be 1 (0x80) for a Long Header
        // Bit 1: Fixed Bit must be 1 (0x40)
        int flags = 0x80 | 0x40;

        // Bits 4-5: Type-Specific bits
        int typeBits;
        if (version == QuicVersion.QUIC_VERSION_2) {
            typeBits = switch (packetType) {
                case INITIAL -> 0b01;
                case ZERO_RTT -> 0b10;
                case HANDSHAKE -> 0b11;
                case RETRY -> 0b00;
                default -> 0;
            };
        } else {
            typeBits = switch (packetType) {
                case INITIAL -> 0b00;
                case ZERO_RTT -> 0b01;
                case HANDSHAKE -> 0b10;
                case RETRY -> 0b11;
                default -> 0;
            };
        }
        flags |= (typeBits << 4);

        // Bits 6-7: Packet Number Length (Mapped from 1-4 bytes to 0-3 index)
        int pnLengthBits = pnLength - 1;
        flags |= pnLengthBits;

        return (byte) flags;
    }

    private static byte buildShortHeaderFlags(byte spinBit, byte keyPhase, int pnLength) {
        // Bit 0: Header Form is 0 (Short Header)
        // Bit 1: Fixed Bit must be 1 (0x40)
        int flags = 0x40;

        // Bit 2: Set the Spin Bit (shifted left by 5 bits)
        flags |= (spinBit  << 5);

        // Bit 5: Set the Key Phase bit (shifted left by 2 bits)
        flags |= (keyPhase  << 2);

        // Bits 6-7: Packet Number Length (Mapped from actual 1-4 bytes to 0-3 index)
        int pnLengthBits = pnLength - 1;
        flags |= pnLengthBits;

        return (byte) flags;
    }
}

