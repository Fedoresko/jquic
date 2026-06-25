package org.fmalyshev.quic;

import org.fmalyshev.quic.streamapi.StreamFrameListener;

import java.nio.ByteBuffer;

import static org.fmalyshev.quic.streamapi.impl.StreamFrameProcessor.FRAME_TYPE_STREAM;

class StreamFrameCallbackListener implements PacketNumberSpace.AckCallback {
    private final StreamFrameListener streamFrameListener;
    private final long connectionId;

    public StreamFrameCallbackListener(StreamFrameListener streamFrameListener, long connectionId) {
        this.streamFrameListener = streamFrameListener;
        this.connectionId = connectionId;
    }

    @Override
    public void onPacketAcknowledged(long packetNumber, PacketNumberSpace.SentPacket packet) {
        ByteBuffer payload = packet.getUnencryptedPayload().duplicate();
        while (payload.hasRemaining()) {
            byte ackedFrameType = payload.get();
            // Check if this is a STREAM frame (0x08-0x0f)
            if ((ackedFrameType & FRAME_TYPE_STREAM) != 0) {
                boolean hasLength = (ackedFrameType & 0x02) != 0;
                long streamId = QuicVarint.read(payload);
                long length = (hasLength) ? QuicVarint.read(payload) : payload.remaining();

                streamFrameListener.onAckReceived(connectionId, streamId, length);

                payload.position(Math.min(payload.limit(), payload.position() + (int) length));
            }
        }
    }
}
