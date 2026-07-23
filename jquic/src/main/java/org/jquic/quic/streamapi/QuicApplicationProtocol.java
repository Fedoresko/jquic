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

import org.jquic.quic.streamapi.congestion.BBRv3;
import org.jspecify.annotations.Nullable;

import java.util.function.Function;

public interface QuicApplicationProtocol {
    /**
     * Returns the name of the application protocol.
     */
    String getProtocolName();
    /**
     * Returns the maximum number of bidirectional streams per connection simultaneously.
     */
    Integer getMaxBidirectionalStreamsPerConnection();
    /**
     * Returns the maximum number of unidirectional streams per connection simultaneously.
     */
    Integer getMaxUnidirectionalStreamsPerConnection();
    /**
     * Returns the maximum size of data that can be buffered for a single stream (unacknowleged packets).
     */
    Integer getMaxStreamData();
    /**
     * Returns the maximum size of data that can be buffered for a single connection (unacknowleged packets).
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

    /**
     * Returns Congestion Control algorithm. Use some of the available or create your own.
     * @return instance of CongestionControl algorithm of choice.
     */
    default CongestionControl getCongestionControl() {
        return new BBRv3();
    }
}

