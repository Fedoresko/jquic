package org.fmalyshev.quic.streamapi;

import java.util.List;

public interface QuicStreamEngine {
    void registerProtocol(QuicApplicationProtocol protocol);
    void unregisterProtocol(String protocolName);
    List<QuicApplicationProtocol> getProtocols();
}
