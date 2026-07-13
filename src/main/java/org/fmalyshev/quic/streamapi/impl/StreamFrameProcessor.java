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
     * Encodes a RESET_STREAM frame (RFC 9000 Section 19.4).
     * Format: type(0x04) | stream_id | error_code | final_size
     */
    public static ByteBuffer encodeResetStreamFrame(long streamId, long errorCode, long finalSize) {
        logger.debug("Encoding reset stream frame for stream id {}", streamId);
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
     * Encodes a MAX_DATA frame (connection-level flow control).
     * Frame type: 0x10
     * Format: type(0x10) | maximum_data
     */
    public static ByteBuffer encodeMaxDataFrame(long maximumData) {
        logger.warn("maximum data frame is {}", maximumData);
        ByteBuffer buffer = ByteBuffer.allocate(1 + 8);
        buffer.put(FRAME_TYPE_MAX_DATA);
        QuicVarint.write(buffer, maximumData);
        buffer.flip();
        return buffer;
    }

    /**
     * Encodes a DATA_BLOCKED frame (connection-level flow control).
     * Frame type: 0x14
     */
    public static ByteBuffer encodeDataBlockedFrame(long limit) {
        logger.warn("Encoding data blocked frame");
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
        logger.warn("Stream {} has stop sending", streamId);
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
        logger.warn("Stream {} has stream data", streamId);
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
        return buffer.flip();
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
        logger.warn("Stream {} has stream data", streamId);
        ByteBuffer buffer = ByteBuffer.allocate(1 + 16);
        buffer.put(FRAME_TYPE_STREAM_DATA_BLOCKED);
        QuicVarint.write(buffer, streamId);
        QuicVarint.write(buffer, limit);
        buffer.flip();
        return buffer;
    }
}
