package org.fmalyshev.quic.streamapi.frames;

public class ResetStreamFrameData implements StreamFrame {
    public final long streamId;
    public final long errorCode;
    public final long finalSize;

    public ResetStreamFrameData(long streamId, long errorCode, long finalSize) {
        this.streamId = streamId;
        this.errorCode = errorCode;
        this.finalSize = finalSize;
    }

    @Override
    public int size() {
        return 24;
    }
}
