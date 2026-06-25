package org.fmalyshev.quic.streamapi;

import java.nio.ByteBuffer;
import java.util.function.Consumer;

public interface QuicStreamResponse {
    enum StreamType {
        Bidirectional,
        Unidirectional
    }

    /**
     * Closes the connection with the specified error code and reason.
     * @param errorCode - application level error code for CONNECTION_CLOSE frame
     * @param reason - reason for closing the connection
     * @throws QuicStreamException
     */
    void closeConnection(long errorCode, String reason) throws QuicStreamException;

    /**
     * Opens a new stream of the specified type.
     * @param streamType - type of the stream (unidirectional or bidirectional)
     * @return - streamId of created stream
     * @throws QuicStreamException
     */
    long openStream(StreamType streamType) throws QuicStreamException;

    /**
     * Request stream termination by sending STOP_SENDING frame.
     * @param streamId - unique stream identifier (per connection)
     * @param errorCode - application level error code from STOP_SENDING frame
     * @throws QuicStreamException
     */
    void closeStream(long streamId, long errorCode) throws QuicStreamException;

    /**
     * Sends data on the specified stream.
     * @param writer - source of data
     * @param fin - true if this is the last frame in the stream (FIN)
     * @throws QuicStreamException
     */
    void sendData(long streamId, Consumer<ByteBuffer> writer, boolean fin) throws QuicStreamException;
}
