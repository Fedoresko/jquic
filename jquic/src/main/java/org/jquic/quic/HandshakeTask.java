package org.jquic.quic;

import org.jquic.quic.buffers.PoolBuffer;

import java.net.SocketAddress;

/**
 * Encapsulates a handshake task to be processed by any available SelectorThread.
 * The CID is pre-allocated by the AcceptorThread.
 */
public class HandshakeTask {
    final PoolBuffer packet;
    final SocketAddress sender;
    final long allocatedCid;
    final QuicPacketHeader.PacketSummary packetSummary;

    HandshakeTask(PoolBuffer packet, SocketAddress sender, long allocatedCid, QuicPacketHeader.PacketSummary packetSummary) {
        this.packet = packet;
        this.sender = sender;
        this.allocatedCid = allocatedCid;
        this.packetSummary = packetSummary;
    }
}
