package org.jquic.quic.streamapi.frames;

public class MaxStreamDataFrameData implements ProtocolFrame {
    public final long streamId;
    public final long maximumData;

    public MaxStreamDataFrameData(long streamId, long maximumData) {
        this.streamId = streamId;
        this.maximumData = maximumData;
    }

    @Override
    public int size() {
        return 16;
    }
}
