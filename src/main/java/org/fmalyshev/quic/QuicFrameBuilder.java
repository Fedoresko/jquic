package org.fmalyshev.quic;

import org.fmalyshev.quic.buffers.ChunkedOutputStreamWithAmendments;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.stream.Collectors;

public class QuicFrameBuilder {
    public static final int CRYPTO_FRAME_MAX_HEADER_LENGTH = 1 + 8 + 8;
    public static final int MAX_LONG_HEADER_LENGTH = 56;
    public static final int MAX_SHORT_HEADER_LENGTH = 25;
    public static final int INITIAL_PACKET_TOKEN_LENGTH = 0;
    public static final int PING_FRAME_LENGTH = 1;
    private static final Logger log = LoggerFactory.getLogger(QuicFrameBuilder.class);

    /**
     * Creates an ACK frame with multiple ranges (RFC 9000 Section 19.3).
     * Format: type(0x02) | largest_ack(varint) | ack_delay(varint) | ack_range_count(varint) |
     * first_ack_range(varint) | [gap(varint) | ack_range(varint)]*
     */
    public static void writeAckFrameWithRanges(long largestAcknowledged, List<PacketNumberSpace.AckRange> ranges, ByteBuffer out) {
        int start = out.position();

        out.put((byte) 0x02); // ACK frame type
        QuicVarint.write(out, largestAcknowledged);
        QuicVarint.write(out, 0); // ACK Delay (simplified)

        if (ranges.isEmpty()) {
            QuicVarint.write(out, 0); // No ranges
            QuicVarint.write(out, 0);
            out.limit(out.position());
            out.position(start);
            return;
        }

        // Range count (excluding first range)
        QuicVarint.write(out, ranges.size() - 1);

        // First range
        PacketNumberSpace.AckRange firstRange = ranges.get(0);
        long firstRangeLength = firstRange.largest - firstRange.smallest;
        QuicVarint.write(out, firstRangeLength);

        // Additional ranges with gaps
        long previousSmallest = firstRange.smallest;
        for (int i = 1; i < ranges.size(); i++) {
            PacketNumberSpace.AckRange range = ranges.get(i);

            // Gap = previousSmallest - currentLargest - 2
            long gap = previousSmallest - range.largest - 2;
            QuicVarint.write(out, gap);

            // Range length
            long rangeLength = range.largest - range.smallest;
            QuicVarint.write(out, rangeLength);

            previousSmallest = range.smallest;
        }

        while (out.position() < 20) {
            out.put((byte) 0x00); //PADDING
        }

        out.limit(out.position());
        out.position(start);
    }

    /**
     * Creates a CONNECTION_CLOSE frame (RFC 9000 Section 19.19).
     * Format: type(0x1c) | error_code(varint) | frame_type(varint) | reason_length(varint) | reason(*)
     *
     * @param errorCode QUIC error code (e.g., 0x0100 + TLS alert for CRYPTO_ERROR)
     * @param reason    Human-readable error reason
     */
    public static void writeConnectionCloseFrame(ByteBuffer out, long errorCode, String reason) {

        int start = out.position();

        byte[] reasonBytes = reason.getBytes();

        out.put((byte) 0x1c); // CONNECTION_CLOSE (QUIC transport error)
        QuicVarint.write(out, errorCode); // Error code
        QuicVarint.write(out, 0); // Frame type (0 = not triggered by specific frame)
        QuicVarint.write(out, reasonBytes.length); // Reason length
        out.put(reasonBytes); // Reason phrase

        out.limit(out.position());
        out.position(start);
    }

    public static void writeAckFrame(PacketNumberSpace space, ByteBuffer out) {
        List<PacketNumberSpace.AckRange> ackRanges = space.getAckRanges();

        log.debug("PN {} acked ranges {}", space.phase, ackRanges.stream().map(PacketNumberSpace.AckRange::toString).collect(Collectors.joining(", ")));

        long largestAcknowledged = space.getLargestReceivedPacketNumber();
        writeAckFrameWithRanges(largestAcknowledged, ackRanges, out);
    }

//    /**
//     * Creates a CRYPTO frame with the given data.
//     */
//    public static ByteBuffer createCryptoFrame(long offset, ByteBuffer data) {
//        // CRYPTO frame: type(varint) | offset(varint) | length(varint) | data
//        ByteBuffer frame = ByteBuffer.allocate(CRYPTO_FRAME_MAX_HEADER_LENGTH + data.remaining());
//        frame.put((byte) 0x06); // CRYPTO frame type
//        QuicVarint.write(frame, offset);
//        QuicVarint.write(frame, data.remaining());
//        frame.put(data);
//        frame.flip();
//        return frame;
//    }

    public static void prependPingFrame(ByteBuffer data) {
        data.position(data.position() - 1);
        data.put((byte) 0x01);
        data.position(data.position() - 1);
    }

    public static void prependCryptoFrameHeader(long offset, ByteBuffer data) {
        // CRYPTO frame: type(varint) | offset(varint) | length(varint) | data
        int length = data.remaining();
        int headerLen = 1 + QuicVarint.sizeOf(offset) + QuicVarint.sizeOf(length);

        data.position(data.position() - headerLen);
        data.put((byte) 0x06); // CRYPTO frame type
        QuicVarint.write(data, offset);
        QuicVarint.write(data, length);
        data.position(data.position() - headerLen);
    }

    public static void writeHandshakeDoneFrame(ByteBuffer frame) {
        frame.put((byte) 0x1e);
        frame.put((byte) 0x0);
        frame.put((byte) 0x0);
        frame.put((byte) 0x0);
    }

    /**
     * Builds the raw TLS 1.3 HelloRetryRequest (HRR) wire message and wraps it
     * in a QUIC CRYPTO frame (RFC 9000 §19.6).
     *
     * <p>An HRR is a special ServerHello (RFC 8446 §4.1.3) whose Random field equals
     * SHA-256("HelloRetryRequest"). It carries exactly two extensions:
     * <ul>
     *   <li>{@code supported_versions} (0x002b) — advertises TLS 1.3.</li>
     *   <li>{@code key_share} (0x0033) — contains <em>only</em> the preferred group id,
     *       no key material (RFC 8446 §4.2.8), telling the client to retry with that group.</li>
     * </ul>
     *
     * <p>This method is a <em>pure builder</em>: it does not touch the transcript.
     * After obtaining the frame, call
     *
     * @param preferredGroupId IANA NamedGroup id the server wants the client to use
     *                         (e.g. {@code 0x001d} for x25519, {@code 0x0017} for secp256r1)
     */
    public static void writeHelloRetryRequest(ByteBuffer hrr, short preferredGroupId) {
        // ── 4-byte TLS handshake header ───────────────────────────────────────────
        int start = hrr.position();

        hrr.put((byte) 0x02);                    // HandshakeType: server_hello (HRR reuses 0x02)
        int bodyLenPos = hrr.position();
        hrr.put((byte) 0).put((byte) 0).put((byte) 0); // body length — back-filled

        // ── ServerHello body (RFC 8446 §4.1.3) ───────────────────────────────────
        int bodyStart = hrr.position();
        hrr.putShort((short) 0x0303);                     // legacy_version = TLS 1.2
        hrr.put(QuicCrypto.HRR_RANDOM);                              // sentinel random
        hrr.put((byte) 0x00);                             // legacy session_id length = 0
        hrr.putShort((short) QuicCrypto.TLS_AES_128_GCM_SHA256_ID); // cipher suite
        hrr.put((byte) 0x00);                             // legacy compression = null

        int extLenPos = hrr.position();
        hrr.putShort((short) 0);                 // extensions_length — back-filled
        int extStart = hrr.position();

        // supported_versions (0x002b): TLS 1.3
        hrr.putShort((short) 0x002b);
        hrr.putShort((short) 0x0002);
        hrr.putShort((short) QuicCrypto.TLS_VERSION_1_3);

        // key_share (0x0033): selected_group only — no key bytes (RFC 8446 §4.2.8)
        hrr.putShort((short) 0x0033);
        hrr.putShort((short) 0x0002);            // extension data length = 2 (group id only)
        hrr.putShort(preferredGroupId);

        // Back-fill extensions_length
        int extEnd = hrr.position();
        hrr.putShort(extLenPos, (short) (extEnd - extStart));

        // Back-fill body length (3 bytes, big-endian)
        int bodyLen = extEnd - bodyStart;
        hrr.put(bodyLenPos,     (byte) ((bodyLen >> 16) & 0xFF));
        hrr.put(bodyLenPos + 1, (byte) ((bodyLen >>  8) & 0xFF));
        hrr.put(bodyLenPos + 2, (byte) ( bodyLen        & 0xFF));


        // ── Wrap in QUIC CRYPTO frame (RFC 9000 §19.6) ───────────────────────────
        // type(varint=0x06) | offset(varint=0) | length(varint) | data
        int hrrLen = hrr.position() - start;
        int hrrLim = hrr.position();

        int headerLen = QuicVarint.sizeOf(0x06) + QuicVarint.sizeOf(0x00) + QuicVarint.sizeOf(hrrLen);
        hrr.position(hrr.position() - headerLen);
        QuicVarint.write(hrr, 0x06);
        QuicVarint.write(hrr, 0x00);
        QuicVarint.write(hrr, hrrLen);
        hrr.position(hrr.position() - headerLen);
        hrr.limit(hrrLim);
    }

    /**
     * Creates a TLS 1.3 ServerHello message (RFC 8446 Section 4.1.3).
     *
     * <p>The {@code key_share} extension carries {@link ConnectionMetadata#serverEphemeralPublicKey},
     * the server's X25519 ephemeral public key produced by processClientHello,
     * so the client can complete its side of the ECDHE exchange.
     *
     * @param metadata the live {@link ConnectionMetadata} for this connection
     */
    public static void writeServerHello(ChunkedOutputStreamWithAmendments out, ConnectionMetadata metadata) throws IOException {
        // ServerHello wire layout (RFC 8446 §4.1.3):
        //   ProtocolVersion(2) + Random(32) + session_id_len(1)
        //   + CipherSuite(2) + compression(1) + extensions_len(2) + extensions

        short cipherSuiteId = QuicCrypto.getCipherSuiteId(metadata.clientMetadata.selectedCipherSuite);

        byte[] keyShare = metadata.serverEphemeralPublicKey;

        byte[] serverRandom = new byte[32];
        QuicCrypto.secureRandom.get().nextBytes(serverRandom);

        out.write((byte) 0x02); //Server Hello

        int headerLenPos = out.getPos();
        out.write((byte) 0x00);
        out.write((byte) 0x00);
        out.write((byte) 0x00);

        int start = out.getPos();
        out.writeShort((short) 0x0303);           // legacy_version = TLS 1.2 (for compatibility)
        out.write(serverRandom);                  // server random from metadata
        out.write((byte) 0x00);                   // legacy session_id (empty for TLS 1.3)
        out.writeShort(cipherSuiteId);            // selected cipher suite
        out.write((byte) 0x00);                   // legacy compression = null

        int extLenPos = out.getPos();
        out.writeShort((short) 0);                // extensions length placeholder
        int extStart = out.getPos();

        // supported_versions extension (0x002b) — signals TLS 1.3 to the client
        out.writeShort((short) 0x002b);
        out.writeShort((short) 0x0002);
        out.writeShort((short) 0x0304);           // TLS 1.3

        // key_share extension (0x0033) — server's x25519 ephemeral public key
        out.writeShort((short) 0x0033);
        out.writeShort((short) (2 + 2 + keyShare.length)); // group(2) + key_len(2) + key
        out.writeShort(metadata.selectedKeyScheme);
        out.writeShort((short) keyShare.length);
        out.write(keyShare);


        // Back-fill extensions length
        short extLength = (short) (out.getPos() - extStart);
        out.amendAtPos(extLenPos, wrt->wrt.writeShort(extLength));

        int len = out.getPos() - start;
        out.amendAtPos(headerLenPos, wrt-> {
            wrt.write((byte) (len >> 16));
            wrt.write((byte) (len >> 8));
            wrt.write((byte) len);
        });
    }

    /**
     * Creates an ACK frame with ECN fields (RFC 9000 Section 19.3).
     * Format: type(0x03) | largest_ack(varint) | ack_delay(varint) | ack_range_count(varint) |
     * first_ack_range(varint) | [gap(varint) | ack_range(varint)]* |
     * ect0_count(varint) | ect1_count(varint) | ecn_ce_count(varint)
     */
    public static void writeAckEcnFrame(PacketNumberSpace space, ByteBuffer out) {
        int start = out.position();
        List<PacketNumberSpace.AckRange> ranges = space.getAckRanges();
        long largestAcknowledged = space.getLargestReceivedPacketNumber();

        out.put((byte) 0x03); // ACK + ECN frame type
        QuicVarint.write(out, largestAcknowledged);
        QuicVarint.write(out, 0); // ACK Delay (simplified)

        if (ranges.isEmpty()) {
            QuicVarint.write(out, 0); // No additional ranges
            QuicVarint.write(out, 0); // First range length is 0
        } else {
            // Range count (excluding first range)
            QuicVarint.write(out, ranges.size() - 1);

            // First range
            PacketNumberSpace.AckRange firstRange = ranges.get(0);
            long firstRangeLength = firstRange.largest - firstRange.smallest;
            QuicVarint.write(out, firstRangeLength);

            // Additional ranges with gaps
            long previousSmallest = firstRange.smallest;
            for (int i = 1; i < ranges.size(); i++) {
                PacketNumberSpace.AckRange range = ranges.get(i);
                // Gap = previousSmallest - currentLargest - 2
                long gap = previousSmallest - range.largest - 2;
                QuicVarint.write(out, gap);
                // Range length
                long rangeLength = range.largest - range.smallest;
                QuicVarint.write(out, rangeLength);
                previousSmallest = range.smallest;
            }
        }

        // ECN Counts
        QuicVarint.write(out, space.clientEct0Counter);
        QuicVarint.write(out, space.clientEct1Counter);
        QuicVarint.write(out, space.clientEctCeCounter);

        while (out.position() - start < 20) {
            out.put((byte) 0x00); // PADDING
        }

        out.limit(out.position());
        out.position(start);
    }
}
