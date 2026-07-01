package org.fmalyshev.quic.streamapi;

import org.fmalyshev.quic.PacketNumberSpace;
import org.fmalyshev.quic.streamapi.frames.StreamFrame;

public interface ConnectionStreamManager extends PacketNumberSpace.AckCallback {
    void onStreamFrame(StreamFrame frame);
}
