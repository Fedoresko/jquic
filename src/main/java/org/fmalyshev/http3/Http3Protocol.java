package org.fmalyshev.http3;

import org.fmalyshev.quic.streamapi.QuicApplicationProtocol;
import org.fmalyshev.quic.streamapi.QuicApplicationProtocolConnectionHandler;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Function;

/**
 * HTTP/3 protocol implementation.
 * Implements QUIC application protocol interface for HTTP/3.
 */
public class Http3Protocol implements QuicApplicationProtocol {
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
    public Integer getMaxBidirectionalStreamsPerConnection() {
        return MAX_BIDIRECTIONAL_STREAMS;
    }

    @Override
    public Integer getMaxUnidirectionalStreamsPerConnection() {
        return MAX_UNIDIRECTIONAL_STREAMS;
    }

    @Override
    public Integer getMaxStreamData() {
        return MAX_STREAM_DATA;
    }

    @Override
    public Integer getMaxData() {
        return MAX_DATA;
    }

    @Override
    public Function<Long, QuicApplicationProtocolConnectionHandler> getConnectionHandler() {
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
}
