package org.fmalyshev.quic.streamapi;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public interface QuicApplicationProtocolConnectionHandler {
    /**
     * Called when the client or server allocates a new stream.
     * @param streamId - unique stream identifier (per connection)
     * @param response - stream response object, handles response commands for the stream
     * @param isServer - if the server initiated this stream
     * @param streamType - type of the stream (unidirectional or bidirectional)
     */
    void onNewStreamAllocated(long streamId, @NonNull QuicStreamResponse response, boolean isServer, QuicStreamResponse.StreamType streamType);

    /**
     * Called when the client receives data on a stream (STREAM frame) if all previous frames were received (in order).
     * @param streamId - unique stream identifier (per connection)
     * @param response - stream response object, handles response commands for the stream
     * @param isLastData - true if this is the last frame in the stream (FIN) or last frame after STREAM_RESET
     * @param errorCode - optional application level error code associated with the frame if the stream was terminated by STREAM_RESET frame
     * @param data - frame data
     */
    void onStreamDataReceived(long streamId, @NonNull QuicStreamResponse response, byte[] data, boolean isLastData, @Nullable Long errorCode);
}
