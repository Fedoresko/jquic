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
package org.jquic.quic.paths;

import org.jquic.quic.*;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.buffers.WriteBufferPool;
import org.jquic.quic.crypto.QuicCrypto;
import org.jquic.quic.linux.ECT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.util.Deque;
import java.util.LinkedList;

public class DatagramBuilder {
    private static final Logger logger = LoggerFactory.getLogger(DatagramBuilder.class);
    private final ByteBuffer connectionIdBytes;
    private final WriteBufferPool writeBufferPool;
    private final ConnectionPathController connectionPathController;
    private final ECT ectMarking;
    private final SocketAddress dest;
    private final ConnectionMetadata connectionMetadata;
    private DatagramToSend packet;
    private boolean hasAck;
    private boolean hasInitial = false;

    public record DatagramToSend(PacketSource packetSource, PoolBuffer data, ECT ectMarking, SocketAddress dest,
                                 Deque<PacketToSend> linkedPackets) {
    }

    public record PacketToSend(long timestamp, long packetNumber, PoolBuffer payload, boolean ackEliciting,
                               PacketNumberSpace space) {
    }


    public DatagramBuilder(ByteBuffer connectionIdBytes, WriteBufferPool writeBufferPool, ConnectionPathController connectionPathController, ECT ectMarking, SocketAddress dest, ConnectionMetadata connectionMetadata) {
        this.connectionIdBytes = connectionIdBytes;
        this.writeBufferPool = writeBufferPool;
        this.connectionPathController = connectionPathController;
        this.ectMarking = ectMarking;
        this.dest = dest;
        this.connectionMetadata = connectionMetadata;
    }

    public void flushPacket() {
        if (packet != null && packet.data.buf().remaining() > 0) {
            if (hasInitial) {
                ByteBuffer buf = packet.data.buf();
                int size = buf.remaining();
                if (size < 1200) { // Zero padding
                    int start = buf.position();
                    buf.position(buf.limit());
                    buf.limit(buf.capacity());
                    buf.put(new byte[1200 - size]);
                    buf.limit(buf.position());
                    buf.position(start);
                }
                hasInitial = false;
            }
            connectionPathController.appendPacket(packet, hasAck);
            packet = null;
        }
    }

    public void sendPing(PacketNumberSpace space) {
        PoolBuffer poolBuffer = writeBufferPool.requestWriteBuffer();

        int start = poolBuffer.buf().position();
        byte[] packet = new byte[16];
        packet[0] = (byte) 0x01;
        poolBuffer.buf().put(packet);
        poolBuffer.buf().limit(poolBuffer.buf().position());
        poolBuffer.buf().position(start);

        sendPacket(System.currentTimeMillis(), poolBuffer, space, false);
    }

    public void sendPacket(long currentTimestamp, PoolBuffer payload, PacketNumberSpace space, boolean isAck) {
        if (packet == null) {
            packet = new DatagramToSend(PacketSource.NEW, writeBufferPool.requestWriteBuffer(), ectMarking, dest, new LinkedList<>());
            packet.data.buf().limit(packet.data.buf().position());
            hasAck = false;
        }

        long packetNumber = space.allocatePacketNumber();
        hasInitial |= space.phase == PacketNumberSpace.PacketPhase.INITIAL;

        int remaining = (int) connectionMetadata.clientMetadata.maxUdpPayloadSize - packet.data.buf().limit() + packet.data.buf().position();

        if (remaining - payload.buf().remaining() < QuicCrypto.GCM_TAG_LENGTH || (!hasInitial && space.phase == PacketNumberSpace.PacketPhase.HANDSHAKE)) {
            flushPacket();
            packet = new DatagramToSend(PacketSource.NEW, writeBufferPool.requestWriteBuffer(), ectMarking, dest, new LinkedList<>());
            packet.data.buf().limit(packet.data.buf().position());
            hasAck = false;
        }

        hasAck |= isAck;

        int start = packet.data.buf().position();

        try {
            packet.data.buf().position(packet.data.buf().limit());
            packet.data.buf().limit(packet.data.buf().capacity());

            switch (space.phase) {
                case INITIAL -> QuicPacketBuilder.buildInitialPacket(
                        connectionMetadata.quicVersion,
                        packet.data,
                        connectionMetadata.clientCid,      // DCID = connection ID
                        connectionIdBytes,      // SCID = connection ID (server uses same)
                        packetNumber,
                        space.getLargestAckedPacketNumber(),
                        payload.buf().duplicate(),            // Plaintext payload
                        connectionMetadata.serverInitialCrypto.get(connectionMetadata.quicVersion)
                );
                case HANDSHAKE -> QuicPacketBuilder.buildHandshakePacket(
                        connectionMetadata.quicVersion,
                        packet.data,
                        connectionMetadata.clientCid,      // DCID = connection ID
                        connectionIdBytes,      // SCID = connection ID (server uses same)
                        packetNumber,
                        space.getLargestAckedPacketNumber(),
                        payload.buf().duplicate(),            // Plaintext payload
                        connectionMetadata.serverHandshakeCrypto
                );
                case APPLICATION -> QuicPacketBuilder.build1RttPacket(
                        connectionMetadata.quicVersion,
                        packet.data,
                        connectionMetadata.clientCid,
                        packetNumber,
                        space.getLargestAckedPacketNumber(),
                        payload.buf().duplicate(),          // Plaintext payload
                        connectionMetadata.serverApplicationCrypto,
                        connectionMetadata.currentPhase
                );
            }

            packet.data.buf().position(start);
            packet.linkedPackets.offer(new PacketToSend(currentTimestamp, packetNumber, payload, !isAck, space));
        } catch (QuicException e) {
            logger.error("Failed to build packet", e);
        }
    }
}
