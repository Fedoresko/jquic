package org.jquic.quic.streamapi.frames;

import org.jquic.quic.buffers.PoolBuffer;

public class StreamFrameData implements ProtocolFrame {
    public final long streamId;
    public final long offset;
    public final PoolBuffer data;
    public final boolean fin;

    public StreamFrameData(long streamId, long offset, PoolBuffer data, boolean fin) {
        this.streamId = streamId;
        this.offset = offset;
        this.data = data;
        this.fin = fin;
    }

    @Override
    public int size() {
        return 20 + data.buf().remaining();
    }
}
