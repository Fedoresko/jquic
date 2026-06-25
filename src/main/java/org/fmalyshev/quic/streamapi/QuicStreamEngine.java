package org.fmalyshev.quic.streamapi;

public interface QuicStreamEngine {
    void registerProtocol(QuicApplicationProtocol protocol);
    void unregisterProtocol(String protocolName);
}
