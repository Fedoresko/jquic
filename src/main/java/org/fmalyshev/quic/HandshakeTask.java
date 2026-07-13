package org.fmalyshev.quic;

import org.fmalyshev.quic.buffers.PoolBuffer;

import java.net.SocketAddress;

/**
 * Encapsulates a handshake task to be processed by any available SelectorThread.
 * The CID is pre-allocated by the AcceptorThread.
 */
public class HandshakeTask {
    final PoolBuffer packet;
    final SocketAddress sender;
    final long allocatedCid;

    HandshakeTask(PoolBuffer packet, SocketAddress sender, long allocatedCid) {
        this.packet = packet;
        this.sender = sender;
        this.allocatedCid = allocatedCid;
    }
}
