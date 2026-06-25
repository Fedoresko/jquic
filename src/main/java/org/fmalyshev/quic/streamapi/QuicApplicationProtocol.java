package org.fmalyshev.quic.streamapi;

import org.jspecify.annotations.Nullable;

import java.util.function.Function;

public interface QuicApplicationProtocol {
    /**
     * Returns the name of the application protocol.
     */
    String getProtocolName();
    /**
     * Returns the maximum number of bidirectional  streams per connection simultaneously.
     */
    Integer getMaxBidirectionalStreamsPerConnection();
    /**
     * Returns the maximum number of unidirectional streams per connection simultaneously.
     */
    Integer getMaxUnidirectionalStreamsPerConnection();
    /**
     * Returns the maximum size of data that can be in-flight in a single stream (unacknowleged packets).
     */
    Integer getMaxStreamData();
    /**
     * Returns the maximum size of data that can be in-flight in a single connection (unacknowleged packets).
     */
    Integer getMaxData();

    /**
     * Returns a function that creates a new connection handler for the given connection ID.
     */
    Function<Long, QuicApplicationProtocolConnectionHandler> getConnectionHandler();

    /**
     * Called when the connection is closed.
     * @param connectionId - connection ID
     * @param errorCode - optional application level error code associated with the connection close if closed with CONNECTION_CLOSE frame
     * @param reason - optional human-readable reason for the connection close if closed with CONNECTION_CLOSE frame
     */
    void onConnectionClose(long connectionId, @Nullable Long errorCode, @Nullable String reason);
}
