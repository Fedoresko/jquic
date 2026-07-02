package org.fmalyshev.quic.streamapi.frames;

import org.fmalyshev.quic.buffers.PoolBuffer;

public class StreamFrameData implements StreamFrame {
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
