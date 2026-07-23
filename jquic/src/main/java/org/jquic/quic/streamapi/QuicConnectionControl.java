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

public interface QuicConnectionControl {
    enum StreamType {
        Bidirectional,
        Unidirectional
    }

    /**
     * Closes the connection with the specified error code and reason.
     * @param errorCode - application level error code for CONNECTION_CLOSE frame
     * @param reason - reason for closing the connection
     */
    void closeConnection(long errorCode, String reason) throws QuicStreamException;

    /**
     * Opens a new stream of the specified type.
     * @param streamType - type of the stream (unidirectional or bidirectional)
     * @return - streamId of created stream
     */
    long openStream(StreamType streamType) throws QuicStreamException;

    /**
     * Request stream termination by sending STOP_SENDING frame.
     * @param streamId - unique stream identifier (per connection)
     * @param errorCode - application level error code from STOP_SENDING frame
     */
    void closeStream(long streamId, long errorCode) throws QuicStreamException;
}

