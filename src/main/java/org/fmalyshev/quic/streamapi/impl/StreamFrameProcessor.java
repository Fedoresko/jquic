package org.fmalyshev.quic.streamapi.impl;

import org.fmalyshev.quic.QuicVarint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;

/**
 * Handles encoding and decoding of QUIC stream-related frames:
 * STREAM, RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA, MAX_STREAMS,
 * STREAM_DATA_BLOCKED, STREAMS_BLOCKED (RFC 9000 Section 19)
 */
public class StreamFrameProcessor {
    private static final Logger logger = LoggerFactory.getLogger(StreamFrameProcessor.class);

    // Frame types (RFC 9000 Section 19)
    public static final byte FRAME_TYPE_RESET_STREAM = 0x04;
    public static final byte FRAME_TYPE_STOP_SENDING = 0x05;
    public static final byte FRAME_TYPE_STREAM = 0x08; // Base, bits can be set
    public static final byte FRAME_TYPE_MAX_DATA = 0x10;
    public static final byte FRAME_TYPE_MAX_STREAM_DATA = 0x11;
    public static final byte FRAME_TYPE_MAX_STREAMS_BIDI = 0x12;
    public static final byte FRAME_TYPE_MAX_STREAMS_UNI = 0x13;
    public static final byte FRAME_TYPE_DATA_BLOCKED = 0x14;
    public static final byte FRAME_TYPE_STREAM_DATA_BLOCKED = 0x15;
    public static final byte FRAME_TYPE_STREAMS_BLOCKED_BIDI = 0x16;
    public static final byte FRAME_TYPE_STREAMS_BLOCKED_UNI = 0x17;

    /**
     * Encodes a STREAM frame (RFC 9000 Section 19.8).
     * Format: type | stream_id | [offset] | [length] | data
     * Type bits: 0x08 | OFF(0x04) | LEN(0x02) | FIN(0x01)
     */
    public static ByteBuffer encodeStreamFrame(long streamId, long offset, ByteBuffer buffer, boolean fin) {
        int dataLength = buffer.remaining();
        int dataPosition = buffer.position();

        // Frame type with flags
        byte frameType = FRAME_TYPE_STREAM;
        if (offset > 0) frameType |= 0x04; // OFF bit
        frameType |= 0x02; // LEN bit (always include length)
        if (fin) frameType |= 0x01; // FIN bit

        int strIdSize = QuicVarint.sizeOf(streamId);
        int offSize = offset > 0 ? QuicVarint.sizeOf(offset) : 0;
        int dataLenSize = QuicVarint.sizeOf(dataLength);
        int headerLen = 1 + strIdSize + offSize + dataLenSize;


        buffer.position(dataPosition - headerLen);
        buffer.put(frameType);
        QuicVarint.write(buffer, streamId);
        if (offset > 0) {
            QuicVarint.write(buffer, offset);
        }
        QuicVarint.write(buffer, dataLength);

        buffer.position(dataPosition - headerLen);
        return buffer;
    }


    /**
     * Quickly extracts stream ID and data length from STREAM frame for flow control tracking.
     * Does not extract the actual data payload.
     * Buffer position is restored after extraction.
     * 
     * @return array with [streamId, dataLength], or null if parsing fails
     */
    public static long[] extractStreamIdAndLength(ByteBuffer buffer, byte frameType) {
        int savedPosition = buffer.position();
        try {
            boolean hasOffset = (frameType & 0x04) != 0;
            boolean hasLength = (frameType & 0x02) != 0;

            long streamId = QuicVarint.read(buffer);

            // Skip offset if present
            if (hasOffset) {
                QuicVarint.read(buffer);
            }

            long dataLength;
            if (hasLength) {
                dataLength = QuicVarint.read(buffer);
            } else {
                // Length is remaining bytes
                dataLength = buffer.remaining();
            }

            return new long[] { streamId, dataLength };
        } catch (Exception e) {
            return null;
        } finally {
            buffer.position(savedPosition);
        }
    }

    /**
     * Encodes a RESET_STREAM frame (RFC 9000 Section 19.4).
     * Format: type(0x04) | stream_id | error_code | final_size
     */
    public static ByteBuffer encodeResetStreamFrame(long streamId, long errorCode, long finalSize) {
        ByteBuffer buffer = ByteBuffer.allocate(1 + 24);
        buffer.put(FRAME_TYPE_RESET_STREAM);
        QuicVarint.write(buffer, streamId);
        QuicVarint.write(buffer, errorCode);
        QuicVarint.write(buffer, finalSize);
        buffer.flip();
        return buffer;
    }
//
//    /**
//     * Decodes a RESET_STREAM frame.
//     */
//    public static ResetStreamFrameData decodeResetStreamFrame(ByteBuffer buffer) {
//        long streamId = QuicVarint.read(buffer);
//        long errorCode = QuicVarint.read(buffer);
//        long finalSize = QuicVarint.read(buffer);
//        return new ResetStreamFrameData(streamId, errorCode, finalSize);
//    }

    /**
     * Encodes a DATA_BLOCKED frame (connection-level flow control).
     * Frame type: 0x14
     */
    public static ByteBuffer encodeDataBlockedFrame(long limit) {
        ByteBuffer buffer = ByteBuffer.allocate(128);
        buffer.put((byte) 0x14); // DATA_BLOCKED frame type
        QuicVarint.write(buffer, limit);
        buffer.flip();
        return buffer;
    }

    /**
     * Encodes a STOP_SENDING frame (RFC 9000 Section 19.5).
     * Format: type(0x05) | stream_id | error_code
     */
    public static ByteBuffer encodeStopSendingFrame(long streamId, long errorCode) {
        ByteBuffer buffer = ByteBuffer.allocate(1 + 16);
        buffer.put(FRAME_TYPE_STOP_SENDING);
        QuicVarint.write(buffer, streamId);
        QuicVarint.write(buffer, errorCode);
        buffer.flip();
        return buffer;
    }

//    /**
//     * Decodes a STOP_SENDING frame.
//     */
//    public static StopSendingFrameData decodeStopSendingFrame(ByteBuffer buffer) {
//        long streamId = QuicVarint.read(buffer);
//        long errorCode = QuicVarint.read(buffer);
//        return new StopSendingFrameData(streamId, errorCode);
//    }

    /**
     * Encodes a MAX_STREAM_DATA frame (RFC 9000 Section 19.10).
     * Format: type(0x11) | stream_id | maximum_data
     */
    public static ByteBuffer encodeMaxStreamDataFrame(long streamId, long maximumData) {
        ByteBuffer buffer = ByteBuffer.allocate(1 + 16);
        buffer.put(FRAME_TYPE_MAX_STREAM_DATA);
        QuicVarint.write(buffer, streamId);
        QuicVarint.write(buffer, maximumData);
        buffer.flip();
        return buffer;
    }

//    /**
//     * Decodes a MAX_STREAM_DATA frame.
//     */
//    public static MaxStreamDataFrameData decodeMaxStreamDataFrame(ByteBuffer buffer) {
//        long streamId = QuicVarint.read(buffer);
//        long maximumData = QuicVarint.read(buffer);
//        return new MaxStreamDataFrameData(streamId, maximumData);
//    }
//
    /**
     * Encodes a MAX_STREAMS frame (RFC 9000 Section 19.11).
     * Format: type(0x12/0x13) | maximum_streams
     */
    public static ByteBuffer encodeMaxStreamsFrame(long maximumStreams, boolean bidirectional) {
        ByteBuffer buffer = ByteBuffer.allocate(1 + 8);
        buffer.put(bidirectional ? FRAME_TYPE_MAX_STREAMS_BIDI : FRAME_TYPE_MAX_STREAMS_UNI);
        QuicVarint.write(buffer, maximumStreams);
        buffer.flip();
        return buffer;
    }
//
//    /**
//     * Decodes a MAX_STREAMS frame.
//     */
//    public static MaxStreamsFrameData decodeMaxStreamsFrame(ByteBuffer buffer) {
//        long maximumStreams = QuicVarint.read(buffer);
//        return new MaxStreamsFrameData(maximumStreams);
//    }

    /**
     * Encodes a STREAM_DATA_BLOCKED frame (RFC 9000 Section 19.13).
     * Format: type(0x15) | stream_id | limit
     */
    public static ByteBuffer encodeStreamDataBlockedFrame(long streamId, long limit) {
        ByteBuffer buffer = ByteBuffer.allocate(1 + 16);
        buffer.put(FRAME_TYPE_STREAM_DATA_BLOCKED);
        QuicVarint.write(buffer, streamId);
        QuicVarint.write(buffer, limit);
        buffer.flip();
        return buffer;
    }
//
//    /**
//     * Decodes a STREAM_DATA_BLOCKED frame.
//     */
//    public static StreamDataBlockedFrameData decodeStreamDataBlockedFrame(ByteBuffer buffer) {
//        long streamId = QuicVarint.read(buffer);
//        long limit = QuicVarint.read(buffer);
//        return new StreamDataBlockedFrameData(streamId, limit);
//    }
//
//    /**
//     * Encodes a STREAMS_BLOCKED frame (RFC 9000 Section 19.14).
//     * Format: type(0x16/0x17) | limit
//     */
//    public static ByteBuffer encodeStreamsBlockedFrame(long limit, boolean bidirectional) {
//        ByteBuffer buffer = ByteBuffer.allocate(1 + 8);
//        buffer.put(bidirectional ? FRAME_TYPE_STREAMS_BLOCKED_BIDI : FRAME_TYPE_STREAMS_BLOCKED_UNI);
//        QuicVarint.write(buffer, limit);
//        buffer.flip();
//        return buffer;
//    }
//
//    /**
//     * Decodes a STREAMS_BLOCKED frame.
//     */
//    public static StreamsBlockedFrameData decodeStreamsBlockedFrame(ByteBuffer buffer) {
//        long limit = QuicVarint.read(buffer);
//        return new StreamsBlockedFrameData(limit);
//    }
//
    public interface StreamFrame {
        int size();
    };

    // Data classes for decoded frames

    public static class StreamFrameData implements StreamFrame {
        public final long streamId;
        public final long offset;
        public final ByteBuffer data;
        public final boolean fin;

        public StreamFrameData(long streamId, long offset, ByteBuffer data, boolean fin) {
            this.streamId = streamId;
            this.offset = offset;
            this.data = data;
            this.fin = fin;
        }

        @Override
        public int size() {
            return 20 + data.remaining();
        }
    }

    public static class ResetStreamFrameData implements StreamFrame {
        public final long streamId;
        public final long errorCode;
        public final long finalSize;

        public ResetStreamFrameData(long streamId, long errorCode, long finalSize) {
            this.streamId = streamId;
            this.errorCode = errorCode;
            this.finalSize = finalSize;
        }

        @Override
        public int size() {
            return 24;
        }
    }

    public static class StopSendingFrameData implements StreamFrame {
        public final long streamId;
        public final long errorCode;

        public StopSendingFrameData(long streamId, long errorCode) {
            this.streamId = streamId;
            this.errorCode = errorCode;
        }

        @Override
        public int size() {
            return 16;
        }
    }

    public static class MaxStreamDataFrameData implements StreamFrame {
        public final long streamId;
        public final long maximumData;

        public MaxStreamDataFrameData(long streamId, long maximumData) {
            this.streamId = streamId;
            this.maximumData = maximumData;
        }

        @Override
        public int size() {
            return 16;
        }
    }

    public static class MaxStreamsFrameData implements StreamFrame {
        public final long maximumStreams;
        public final boolean bidirectional;

        public MaxStreamsFrameData(long maximumStreams, boolean bidirectional) {
            this.maximumStreams = maximumStreams;
            this.bidirectional = bidirectional;
        }

        @Override
        public int size() {
            return 12;
        }
    }

    public static class StreamDataBlockedFrameData implements StreamFrame {
        public final long streamId;
        public final long limit;

        public StreamDataBlockedFrameData(long streamId, long limit) {
            this.streamId = streamId;
            this.limit = limit;
        }

        @Override
        public int size() {
            return 16;
        }
    }

    public static class StreamsBlockedFrameData implements StreamFrame {
        public final long limit;
        public final boolean bidirectional;

        public StreamsBlockedFrameData(long limit, boolean bidirectional) {
            this.limit = limit;
            this.bidirectional = bidirectional;
        }

        @Override
        public int size() {
            return 12;
        }
    }
}
