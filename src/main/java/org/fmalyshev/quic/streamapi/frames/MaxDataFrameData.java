package org.fmalyshev.quic.streamapi.frames;

public class MaxDataFrameData implements StreamFrame {
    public final long maximumData;

    public MaxDataFrameData(long maximumData) {
        this.maximumData = maximumData;
    }

    @Override
    public int size() {
        return 8;
    }
}
