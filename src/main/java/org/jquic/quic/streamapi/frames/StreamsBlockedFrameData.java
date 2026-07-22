package org.jquic.quic.streamapi.frames;

public class StreamsBlockedFrameData implements ProtocolFrame {
    public final long limit;
    public final boolean bidirectional;

    public StreamsBlockedFrameData(long limit, boolean bidirectional) {
        this.limit = limit;
        this.bidirectional = bidirectional;
    }

    @Override
    public int size() {
        return 12;
    }
}
