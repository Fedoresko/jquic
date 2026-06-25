package org.fmalyshev.quic;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;

/**
 * Stub for connection-level and stream-level flow control frame handling.
 * Processes RFC 9000 frames: RESET_STREAM (0x04), STOP_SENDING (0x05),
 * MAX_DATA (0x10), MAX_STREAM_DATA (0x11), MAX_STREAMS (0x12-0x13),
 * DATA_BLOCKED (0x14), STREAM_DATA_BLOCKED (0x15), STREAMS_BLOCKED (0x16-0x17).
 */
public class QuicConnectionFlowControl {

    private static final Logger logger = LoggerFactory.getLogger(QuicConnectionFlowControl.class);

    private final long connectionId;

    public QuicConnectionFlowControl(long connectionId) {
        this.connectionId = connectionId;
    }

    /**
     * Handles a flow-control or stream-reset frame.
     *
     * @param frameType    The frame type byte
     * @param framePayload ByteBuffer positioned at the start of the frame payload (after frame type byte)
     */
    public void onFlowControlFrame(byte frameType, ByteBuffer framePayload) {
        switch (frameType & 0xFF) {
            case 0x04 -> handleResetStream(framePayload);
            case 0x05 -> handleStopSending(framePayload);
            case 0x10 -> handleMaxData(framePayload);
            case 0x11 -> handleMaxStreamData(framePayload);
            case 0x12, 0x13 -> handleMaxStreams(frameType, framePayload);
            case 0x14 -> handleDataBlocked(framePayload);
            case 0x15 -> handleStreamDataBlocked(framePayload);
            case 0x16, 0x17 -> handleStreamsBlocked(frameType, framePayload);
            default -> logger.warn("CID {}: unknown flow-control frame type 0x{}", connectionId,
                    String.format("%02x", frameType));
        }
    }

    /** RESET_STREAM (0x04): stream abruptly terminated by sender. */
    private void handleResetStream(ByteBuffer payload) {
        long streamId   = QuicVarint.read(payload);
        long errorCode  = QuicVarint.read(payload);
        long finalSize  = QuicVarint.read(payload);
        logger.info("CID {}: RESET_STREAM streamId={} errorCode={} finalSize={}",
                connectionId, streamId, errorCode, finalSize);
        // TODO: notify stream engine, update flow-control accounting
    }

    /** STOP_SENDING (0x05): peer requests halt of stream sending. */
    private void handleStopSending(ByteBuffer payload) {
        long streamId  = QuicVarint.read(payload);
        long errorCode = QuicVarint.read(payload);
        logger.info("CID {}: STOP_SENDING streamId={} errorCode={}",
                connectionId, streamId, errorCode);
        // TODO: notify stream engine
    }

    /** MAX_DATA (0x10): connection-level send limit increase. */
    private void handleMaxData(ByteBuffer payload) {
        long maxData = QuicVarint.read(payload);
        logger.info("CID {}: MAX_DATA maxData={}", connectionId, maxData);
        // TODO: update connection send window
    }

    /** MAX_STREAM_DATA (0x11): per-stream send limit increase. */
    private void handleMaxStreamData(ByteBuffer payload) {
        long streamId     = QuicVarint.read(payload);
        long maxStreamData = QuicVarint.read(payload);
        logger.info("CID {}: MAX_STREAM_DATA streamId={} maxStreamData={}",
                connectionId, streamId, maxStreamData);
        // TODO: update per-stream send window
    }

    /** MAX_STREAMS (0x12 bidirectional, 0x13 unidirectional). */
    private void handleMaxStreams(byte frameType, ByteBuffer payload) {
        long maxStreams = QuicVarint.read(payload);
        String direction = (frameType == 0x12) ? "bidirectional" : "unidirectional";
        logger.info("CID {}: MAX_STREAMS ({}) maxStreams={}", connectionId, direction, maxStreams);
        // TODO: update max streams limit
    }

    /** DATA_BLOCKED (0x14): sender is blocked at connection level. */
    private void handleDataBlocked(ByteBuffer payload) {
        long dataLimit = QuicVarint.read(payload);
        logger.info("CID {}: DATA_BLOCKED dataLimit={}", connectionId, dataLimit);
        // TODO: issue MAX_DATA frame
    }

    /** STREAM_DATA_BLOCKED (0x15): sender is blocked at stream level. */
    private void handleStreamDataBlocked(ByteBuffer payload) {
        long streamId  = QuicVarint.read(payload);
        long dataLimit = QuicVarint.read(payload);
        logger.info("CID {}: STREAM_DATA_BLOCKED streamId={} dataLimit={}",
                connectionId, streamId, dataLimit);
        // TODO: issue MAX_STREAM_DATA frame
    }

    /** STREAMS_BLOCKED (0x16 bidirectional, 0x17 unidirectional). */
    private void handleStreamsBlocked(byte frameType, ByteBuffer payload) {
        long streamLimit = QuicVarint.read(payload);
        String direction = (frameType == 0x16) ? "bidirectional" : "unidirectional";
        logger.info("CID {}: STREAMS_BLOCKED ({}) streamLimit={}", connectionId, direction, streamLimit);
        // TODO: issue MAX_STREAMS frame
    }
}
