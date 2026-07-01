package org.fmalyshev.quic.streamapi.frames;

public class StreamDataBlockedFrameData implements StreamFrame {
    public final long streamId;
    public final long limit;

    public StreamDataBlockedFrameData(long streamId, long limit) {
        this.streamId = streamId;
        this.limit = limit;
    }

    @Override
    public int size() {
        return 16;
    }
}
