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
package org.jquic.http3;

import org.jquic.quic.streamapi.CongestionControl;
import org.jquic.quic.streamapi.QuicApplicationProtocol;
import org.jquic.quic.streamapi.QuicApplicationProtocolConnectionHandler;
import org.jquic.quic.streamapi.congestion.BBRv3;
import org.jquic.quic.streamapi.congestion.TcpPrague;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.function.Function;

/**
 * HTTP/3 protocol implementation.
 * Implements QUIC application protocol interface for HTTP/3.
 */
public class Http3Protocol implements QuicApplicationProtocol<Serializable> {
    private static final Logger logger = LoggerFactory.getLogger(Http3Protocol.class);

    private static final String PROTOCOL_NAME = "h3";
    private static final int MAX_BIDIRECTIONAL_STREAMS = 100;
    private static final int MAX_UNIDIRECTIONAL_STREAMS = 100;
    private static final int MAX_STREAM_DATA = 1024 * 1024; // 1 MB
    private static final int MAX_DATA = 10 * 1024 * 1024; // 10 MB

    private final Http3RequestHandler requestHandler;

    public Http3Protocol(Http3RequestHandler requestHandler) {
        this.requestHandler = requestHandler;
    }

    @Override
    public String getProtocolName() {
        return PROTOCOL_NAME;
    }

    @Override
    public int getMaxBidirectionalStreamsPerConnection() {
        return MAX_BIDIRECTIONAL_STREAMS;
    }

    @Override
    public int getMaxUnidirectionalStreamsPerConnection() {
        return MAX_UNIDIRECTIONAL_STREAMS;
    }

    @Override
    public int getMaxStreamData() {
        return MAX_STREAM_DATA;
    }

    @Override
    public int getMaxData() {
        return MAX_DATA;
    }

    @Override
    public Function<Long, QuicApplicationProtocolConnectionHandler<Serializable>> getConnectionHandler() {
        return connectionId -> {
            logger.debug("Creating HTTP/3 connection handler for connection {}", connectionId);
            return new Http3ConnectionHandler(connectionId, requestHandler);
        };
    }

    @Override
    public void onConnectionClose(long connectionId, @Nullable Long errorCode, @Nullable String reason) {
        if (errorCode != null && reason != null) {
            logger.info("HTTP/3 connection {} closed with error {}: {}", connectionId, errorCode, reason);
        } else {
            logger.info("HTTP/3 connection {} closed", connectionId);
        }
    }

    @Override
    public CongestionControl getCongestionControl() {
        return new TcpPrague();
    }
}

