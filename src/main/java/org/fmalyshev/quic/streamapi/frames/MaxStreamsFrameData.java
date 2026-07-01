package org.fmalyshev.quic.streamapi.frames;

public class MaxStreamsFrameData implements StreamFrame {
    public final long maximumStreams;
    public final boolean bidirectional;

    public MaxStreamsFrameData(long maximumStreams, boolean bidirectional) {
        this.maximumStreams = maximumStreams;
        this.bidirectional = bidirectional;
    }

    @Override
    public int size() {
        return 12;
    }
}
