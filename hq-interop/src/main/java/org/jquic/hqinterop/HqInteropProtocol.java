package org.jquic.hqinterop;

import org.jquic.quic.streamapi.CongestionControl;
import org.jquic.quic.streamapi.QuicApplicationProtocol;
import org.jquic.quic.streamapi.QuicApplicationProtocolConnectionHandler;
import org.jquic.quic.streamapi.congestion.TcpPrague;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Function;
 
public class HqInteropProtocol implements QuicApplicationProtocol {
    private static final Logger logger = LoggerFactory.getLogger(HqInteropProtocol.class);
 
    private static final String PROTOCOL_NAME = "hq-interop";
    private static final int MAX_BIDIRECTIONAL_STREAMS = 100;
    private static final int MAX_UNIDIRECTIONAL_STREAMS = 10;
    private static final int MAX_STREAM_DATA = 1024 * 1024; // 1 MB
    private static final int MAX_DATA = 10 * 1024 * 1024; // 10 MB
 
    private final HqInteropRequestHandler requestHandler;

    public HqInteropProtocol(HqInteropRequestHandler requestHandler) {
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
    public Function<Long, QuicApplicationProtocolConnectionHandler> getConnectionHandler() {
        return connectionId -> {
            logger.debug("Creating hq-interop connection handler for connection {}", connectionId);
            return new HqInteropConnectionHandler(requestHandler);
        };
    }
 
    @Override
    public void onConnectionClose(long connectionId, @Nullable Long errorCode, @Nullable String reason) {
        if (errorCode != null && reason != null) {
            logger.info("hq-interop connection {} closed with error {}: {}", connectionId, errorCode, reason);
        } else {
            logger.info("hq-interop connection {} closed", connectionId);
        }
    }

    @Override
    public CongestionControl getCongestionControl() {
        return new TcpPrague();
    }
}
