package org.fmalyshev.quic.streamapi;

import org.fmalyshev.quic.streamapi.impl.StreamFrameProcessor;

import java.nio.ByteBuffer;

/**
 * Listener interface for receiving stream-related frames from QUIC connection.
 * Called from selector thread and should enqueue events for worker processing.
 */
public interface StreamFrameListener {
    /**
     * Called when a stream-related frame is received.
     * The buffer is positioned at the start of the frame payload (after frame type byte).
     *
     * @param connectionId The connection ID
     */
    void onStreamFrame(long connectionId, StreamFrameProcessor.StreamFrame frame);

    /**
     * Called when packets are acknowledged to update stream flow control.
     * This is called from selector thread and should enqueue ACK event for worker processing.
     *
     * @param connectionId       The connection ID
     */
    void onAckReceived(long connectionId, long streamId, long dataLength);
}
