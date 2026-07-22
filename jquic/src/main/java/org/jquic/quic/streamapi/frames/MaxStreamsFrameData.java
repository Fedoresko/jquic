package org.jquic.quic.streamapi.frames;

public class MaxStreamsFrameData implements ProtocolFrame {
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
