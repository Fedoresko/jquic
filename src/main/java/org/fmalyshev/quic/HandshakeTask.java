package org.fmalyshev.quic;

import java.net.SocketAddress;
import java.nio.ByteBuffer;

/**
 * Encapsulates a handshake task to be processed by any available SelectorThread.
 * The CID is pre-allocated by the AcceptorThread.
 */
class HandshakeTask {
    final ByteBuffer packet;
    final SocketAddress sender;
    final long allocatedCid;

    HandshakeTask(ByteBuffer packet, SocketAddress sender, long allocatedCid) {
        this.packet = packet;
        this.sender = sender;
        this.allocatedCid = allocatedCid;
    }
}
