package org.fmalyshev.quic.streamapi.frames;

public class StopSendingFrameData implements StreamFrame {
    public final long streamId;
    public final long errorCode;

    public StopSendingFrameData(long streamId, long errorCode) {
        this.streamId = streamId;
        this.errorCode = errorCode;
    }

    @Override
    public int size() {
        return 16;
    }
}
