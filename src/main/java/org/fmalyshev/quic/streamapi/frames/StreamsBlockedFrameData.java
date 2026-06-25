package org.fmalyshev.quic.streamapi.frames;

import org.fmalyshev.quic.streamapi.StreamFrameListener;

public class StreamsBlockedFrameData implements StreamFrameListener.StreamFrame {
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
