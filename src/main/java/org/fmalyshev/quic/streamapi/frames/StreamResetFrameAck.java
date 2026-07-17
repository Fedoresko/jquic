package org.fmalyshev.quic.streamapi.frames;

public class StreamResetFrameAck implements StreamFrame{
    public StreamResetFrameAck(long streamId) {
        this.streamId = streamId;
    }

    @Override
    public int size() {
        return 0;
    }

    public final long streamId;
}
