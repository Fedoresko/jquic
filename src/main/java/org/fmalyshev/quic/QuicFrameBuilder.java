package org.fmalyshev.quic;

import java.nio.ByteBuffer;
import java.util.List;

public class QuicFrameBuilder {
    /**
     * Creates an ACK frame with multiple ranges (RFC 9000 Section 19.3).
     * Format: type(0x02) | largest_ack(varint) | ack_delay(varint) | ack_range_count(varint) |
     * first_ack_range(varint) | [gap(varint) | ack_range(varint)]*
     */
    public static ByteBuffer createAckFrameWithRanges(long largestAcknowledged, List<PacketNumberSpace.AckRange> ranges) {
        ByteBuffer frame = ByteBuffer.allocate(256);

        frame.put((byte) 0x02); // ACK frame type
        QuicVarint.write(frame, largestAcknowledged);
        QuicVarint.write(frame, 0); // ACK Delay (simplified)

        if (ranges.isEmpty()) {
            QuicVarint.write(frame, 0); // No ranges
            QuicVarint.write(frame, 0);
            frame.flip();
            return frame;
        }

        // Range count (excluding first range)
        QuicVarint.write(frame, ranges.size() - 1);

        // First range
        PacketNumberSpace.AckRange firstRange = ranges.get(0);
        long firstRangeLength = firstRange.largest - firstRange.smallest;
        QuicVarint.write(frame, firstRangeLength);

        // Additional ranges with gaps
        long previousSmallest = firstRange.smallest;
        for (int i = 1; i < ranges.size(); i++) {
            PacketNumberSpace.AckRange range = ranges.get(i);

            // Gap = previousSmallest - currentLargest - 2
            long gap = previousSmallest - range.largest - 2;
            QuicVarint.write(frame, gap);

            // Range length
            long rangeLength = range.largest - range.smallest;
            QuicVarint.write(frame, rangeLength);

            previousSmallest = range.smallest;
        }

        frame.flip();
        return frame;
    }

    /**
     * Creates a CONNECTION_CLOSE frame (RFC 9000 Section 19.19).
     * Format: type(0x1c) | error_code(varint) | frame_type(varint) | reason_length(varint) | reason(*)
     *
     * @param errorCode QUIC error code (e.g., 0x0100 + TLS alert for CRYPTO_ERROR)
     * @param reason    Human-readable error reason
     */
    public static ByteBuffer createConnectionCloseFrame(long errorCode, String reason) {
        byte[] reasonBytes = reason.getBytes();
        ByteBuffer frame = ByteBuffer.allocate(32 + reasonBytes.length);

        frame.put((byte) 0x1c); // CONNECTION_CLOSE (QUIC transport error)
        QuicVarint.write(frame, errorCode); // Error code
        QuicVarint.write(frame, 0); // Frame type (0 = not triggered by specific frame)
        QuicVarint.write(frame, reasonBytes.length); // Reason length
        frame.put(reasonBytes); // Reason phrase

        frame.flip();
        return frame;
    }

    public static ByteBuffer createAckFrame(PacketNumberSpace space) {
        List<PacketNumberSpace.AckRange> ackRanges = space.getAckRanges();

        long largestAcknowledged = space.getLargestReceivedPacketNumber();
        return createAckFrameWithRanges(largestAcknowledged, ackRanges);
    }

    /**
     * Creates a CRYPTO frame with the given data.
     */
    public static ByteBuffer createCryptoFrame(long offset, ByteBuffer data) {
        // CRYPTO frame: type(varint) | offset(varint) | length(varint) | data
        ByteBuffer frame = ByteBuffer.allocate(1 + 8 + 8 + data.remaining());
        frame.put((byte) 0x06); // CRYPTO frame type
        QuicVarint.write(frame, offset);
        QuicVarint.write(frame, data.remaining());
        frame.put(data);
        frame.flip();
        return frame;
    }

    public static ByteBuffer createHandshakeDoneFrame() {
        ByteBuffer frame = ByteBuffer.allocate(4);
        frame.put((byte) 0x1e);
        frame.put((byte) 0x0);
        frame.put((byte) 0x0);
        frame.put((byte) 0x0);
        frame.flip();
        return frame;
    }
}
