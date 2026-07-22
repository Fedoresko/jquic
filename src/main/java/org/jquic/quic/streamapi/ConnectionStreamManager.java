package org.jquic.quic.streamapi;

import org.jquic.quic.PacketNumberSpace;
import org.jquic.quic.streamapi.frames.ProtocolFrame;

public interface ConnectionStreamManager extends PacketNumberSpace.AckCallback {
    void onProtocolFrame(ProtocolFrame frame);
    void onDataSend(int dataSize);

    void onConnectionClose();
}
