package org.fmalyshev.quic.streamapi.frames;

import org.fmalyshev.quic.streamapi.StreamFrameListener;

import java.nio.ByteBuffer;

public class StreamFrameData implements StreamFrameListener.StreamFrame {
    public final long streamId;
    public final long offset;
    public final ByteBuffer data;
    public final boolean fin;

    public StreamFrameData(long streamId, long offset, ByteBuffer data, boolean fin) {
        this.streamId = streamId;
        this.offset = offset;
        this.data = data;
        this.fin = fin;
    }

    @Override
    public int size() {
        return 20 + data.remaining();
    }
}
