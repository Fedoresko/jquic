/*
 * Copyright 2026 Fedor Malyshev
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jquic.quic;

import org.jquic.quic.packets.PacketNumberSpace;
import org.jquic.quic.streamapi.ConnectionStreamManager;
import org.jquic.quic.streamapi.frames.StreamResetFrameAck;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;

import static org.jquic.quic.QuicFrameBuilder.*;
import static org.jquic.quic.streamapi.impl.StreamFrameWriter.*;

public class AckedPacketsHandler implements PacketNumberSpace.AckCallback {
    private final static Logger log = LoggerFactory.getLogger(AckedPacketsHandler.class);
    private final QuicConnection connection;

    public AckedPacketsHandler(QuicConnection connection) {
        this.connection = connection;
    }

    public static @NonNull SreamFrameDetails parseStreamFrameDetails(byte frameType, ByteBuffer payload) {
        boolean hasLength = (frameType & 0x02) != 0;
        long streamId = QuicVarint.read(payload);
        boolean hasOffset = (frameType & 0x04) != 0;
        long offset = 0;
        if (hasOffset) offset = QuicVarint.read(payload);
        long length = (hasLength) ? QuicVarint.read(payload) : payload.remaining();
        return new SreamFrameDetails(streamId, length, offset);
    }

    @Override
    public void onPacketAcknowledged(long packetNumber, PacketNumberSpace.SentPacket packet) {
        try {
            ByteBuffer payload = packet.getUnencryptedPayload().buf().duplicate();
            while (payload.hasRemaining()) {
                byte frameType = payload.get();
                ConnectionStreamManager connectionStreamManager = connection.getConnectionStreamManager();
                if (frameType >= 0x08 && frameType <= 0x0f) {
                    SreamFrameDetails frameDetails = parseStreamFrameDetails(frameType, payload);
                    // Check if this is a STREAM frame (0x08-0x0f)
                    payload.position(Math.min(payload.limit(), payload.position() + (int) frameDetails.length()));
                    if (connectionStreamManager != null)
                        connectionStreamManager.onStreamAck(frameDetails.streamId(), frameDetails.offset(), frameDetails.length());
                } else if (frameType == FRAME_TYPE_RESET_STREAM) {
                    long streamId = QuicVarint.read(payload);
                    QuicVarint.read(payload);
                    QuicVarint.read(payload);
                    if (connectionStreamManager != null)
                        connectionStreamManager.onProtocolFrame(new StreamResetFrameAck(streamId));
                } else if (frameType == NEW_CONNECTION_ID) {
                    QuicVarint.read(payload);
                    QuicVarint.read(payload); // retirePriorTo
                    int cidLen = payload.get() & 0xFF;
                    payload.position(payload.position() + cidLen + 16);
                } else if (frameType == RETIRE_CONNECTION_ID) {
                    QuicVarint.read(payload);
                } else if (frameType == ACK_ECN) {
                    QuicConnection.parseAckFrame(payload, true);
                    // TODO: probably need notify PN space that peer has received exact ack ranges. 
                } else if (frameType == FRAME_TYPE_STOP_SENDING || frameType == FRAME_TYPE_MAX_STREAM_DATA
                        || frameType == FRAME_TYPE_STREAM_DATA_BLOCKED) {
                    QuicVarint.read(payload);
                    QuicVarint.read(payload);
                } else if (frameType == FRAME_TYPE_MAX_STREAMS_BIDI || frameType == FRAME_TYPE_MAX_STREAMS_UNI ||
                        frameType == FRAME_TYPE_STREAMS_BLOCKED_BIDI || frameType == FRAME_TYPE_STREAMS_BLOCKED_UNI ||
                        frameType == FRAME_TYPE_MAX_DATA || frameType == FRAME_TYPE_DATA_BLOCKED) {
                    QuicVarint.read(payload);
                } else if (frameType == CRYPTO) {
                    QuicVarint.read(payload);
                    long cryptoLength = QuicVarint.read(payload);
                    int cryptoDataLen = (int) Math.min(cryptoLength, payload.remaining());
                    payload.position(payload.position() + cryptoDataLen);
                } else if (frameType == NEW_TOKEN) {
                    long tokenLength = QuicVarint.read(payload);
                    int tokenDataLen = (int) Math.min(tokenLength, payload.remaining());
                    payload.position(payload.position() + tokenDataLen);
                } else if (frameType == PATH_CHALLENGE || frameType == PATH_RESPONSE) {
                    payload.position(payload.position() + 8);
                }
            }
        } catch (Exception ex) {
            log.error("Error while processing packet acknowledged packet", ex);
        }
    }

    public record SreamFrameDetails(long streamId, long length, long offset) {
    }
}
