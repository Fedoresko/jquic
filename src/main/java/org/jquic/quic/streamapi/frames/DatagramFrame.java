package org.jquic.quic.streamapi.frames;

import org.jquic.quic.buffers.PoolBuffer;

public class DatagramFrame implements ProtocolFrame {
    public final PoolBuffer datagram;

    public DatagramFrame(PoolBuffer datagram) {
        this.datagram = datagram;
    }

    @Override
    public int size() {
        return datagram.buf().remaining();
    }
}
