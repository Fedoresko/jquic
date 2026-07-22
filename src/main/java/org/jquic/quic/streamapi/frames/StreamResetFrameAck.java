package org.jquic.quic.streamapi.frames;

public class StreamResetFrameAck implements ProtocolFrame {
    public StreamResetFrameAck(long streamId) {
        this.streamId = streamId;
    }

    @Override
    public int size() {
        return 0;
    }

    public final long streamId;
}
