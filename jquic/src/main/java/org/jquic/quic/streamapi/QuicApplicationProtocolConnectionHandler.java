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
package org.jquic.quic.streamapi;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.io.DataOutputStream;

public interface QuicApplicationProtocolConnectionHandler {
    /**
     * Called when the QUIC connection is fully established and ready for application data.
     * @param control - connection control object to open mandatory protocol streams.
     */
    default void onConnectionEstablished(@NonNull QuicConnectionControl control) {}

    /**
     * Called when the server allocates a new stream.
     * @param streamId - unique stream identifier (per connection)
     * @param streamType - type of the stream (unidirectional or bidirectional)
     * @param outputStream - stream for writing stream frames, blocks writing thread by congestion control and buffer limits.
     */
    void onNewServerStreamAllocated(long streamId, @NonNull DataOutputStream outputStream, QuicConnectionControl.StreamType streamType);

    /**
     * Called when the client allocates a new stream.
     * @param streamId - unique stream identifier (per connection)
     * @param control - connection control object, handles commands like openStream / closeStream / closeConnection
     * @param streamType - type of the stream (unidirectional or bidirectional)
     * @param outputStream - stream for writing stream frames, blocks writing thread by congestion control and buffer limits
     *                      (null for unidirectional streams).
     */
    void onNewClientStreamAllocated(long streamId, @NonNull QuicConnectionControl control, @Nullable DataOutputStream outputStream, QuicConnectionControl.StreamType streamType);

    /**
     * Called when the client receives data on a stream (STREAM frame) if all previous frames were received (in order).
     * @param streamId - unique stream identifier (per connection)
     * @param control - connection control object, handles commands like openStream / closeStream / closeConnection
     * @param isLastData - true if this is the last frame in the stream (FIN) or last frame after STREAM_RESET
     * @param errorCode - optional application level error code associated with the frame if the stream was terminated by STREAM_RESET frame
     * @param data - frame data
     */
    void onStreamDataReceived(long streamId, @NonNull QuicConnectionControl control, byte[] data, boolean isLastData, @Nullable Long errorCode);

    /**
     * Called when DATAGRAM frame is received.
     * @param control - connection control object, handles commands like openStream / closeStream / closeConnection
     * @param data - datagram
     */
    void onDatagramReceived(byte[] data, @NonNull QuicConnectionControl control);

    /**
     * Accepts stream for writing DATAGRAM_FRAME data into connection
     */
    void setOutgoingDatagramStream(@NonNull DataOutputStream outputStream);

    /**
     * Called when connection is closed
     */
    void onConnectionClose();
}

