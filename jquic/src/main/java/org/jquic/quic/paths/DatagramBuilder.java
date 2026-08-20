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
import org.jquic.quic.linux.ECT;
import org.jquic.quic.packets.PacketNumberSpace;
import org.jquic.quic.packets.PacketPhase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.*;

import static org.jquic.quic.crypto.QuicCrypto.GCM_TAG_LENGTH;

public class DatagramBuilder {
    private static final Logger logger = LoggerFactory.getLogger(DatagramBuilder.class);
    private final byte[] connectionIdBytes;
    private final WriteBufferPool writeBufferPool;
    private ECT ectMarking;
    private final ConnectionMetadata connectionMetadata;
    private final List<Frame> framesToSend = new ArrayList<>();
    private DatagramToSend readyPacket;
    private int framesToSendSumLen;
    private final PacketNumberSpace space;

    public void setEct(ECT ectMarking) {
        this.ectMarking = ectMarking;
    }

    public DatagramBuilder(byte [] connectionIdBytes, WriteBufferPool writeBufferPool, ECT ectMarking, ConnectionMetadata connectionMetadata, PacketNumberSpace space) {
        this.connectionIdBytes = connectionIdBytes;
        this.writeBufferPool = writeBufferPool;
        this.ectMarking = ectMarking;
        this.connectionMetadata = connectionMetadata;
        this.space = space;
    }

    public DatagramToSend getPacket(long currentTimeMs, InetSocketAddress dest, boolean forceBuffered, FrameSource frameSource) {
        if (readyPacket == null) {
            while (readyPacket == null && !frameSource.isEmpty()) {
                enqueueOneMoreFrame(currentTimeMs, dest, frameSource.poll());
            }
            if (forceBuffered && readyPacket == null) {
                flushPacket(currentTimeMs, dest);
            }
        }
        DatagramToSend res = readyPacket;
        readyPacket = null;
        return res;
    }

    public void clear() {
        if (readyPacket != null) {
            readyPacket.data().release();
            readyPacket = null;
        }
        for (Frame frame : framesToSend) {
            frame.data().release();
        }
        framesToSend.clear();
    }

    public void flushPacket(long currentTimeMs, InetSocketAddress dest) {
        if (readyPacket != null) {
            throw new IllegalStateException("Packet already flushed");
        }

        PoolBuffer packet = wrapPacket(currentTimeMs, dest);
        if (packet != null) {
            if (space.phase == PacketPhase.INITIAL) {
                ByteBuffer buf = packet.buf();
                int size = buf.remaining();
                if (size < 1200) { // Zero padding
                    int start = buf.position();
                    buf.position(buf.limit());
                    buf.limit(buf.capacity());
                    buf.put(new byte[1200 - size]);
                    buf.limit(buf.position());
                    buf.position(start);
                }
            }
            readyPacket = new DatagramToSend(PacketSource.NEW, packet, ectMarking, dest);
        }
    }

    private void enqueueOneMoreFrame(long currentTimeMs, InetSocketAddress dest, Frame frame) {
        int maxHeaderLen = (space.phase == PacketPhase.APPLICATION) ? QuicFrameBuilder.MAX_SHORT_HEADER_LENGTH : QuicFrameBuilder.MAX_LONG_HEADER_LENGTH;
        int remaining = (int) connectionMetadata.clientMetadata.maxUdpPayloadSize - GCM_TAG_LENGTH - maxHeaderLen - framesToSendSumLen;

        if (remaining < frame.data().buf().remaining() || (space.phase == PacketPhase.HANDSHAKE))
        {
            flushPacket(currentTimeMs, dest);
        }

        framesToSendSumLen += frame.data().buf().remaining();
        framesToSend.add(frame);
    }

    public PoolBuffer wrapPacket(long currentTimestamp, InetSocketAddress dest) {
        if (framesToSend.isEmpty())
            return null;

        PoolBuffer payload = writeBufferPool.requestWriteBuffer();

        boolean ackEliciting = false;
        int start = payload.buf().position();
        while (! framesToSend.isEmpty()) {
            Frame frame = framesToSend.removeFirst();
            ackEliciting |= frame.ackEliciting();
            int reminder = payload.buf().remaining();
            try {
                payload.buf().put(frame.data().buf());
            } catch (BufferOverflowException e) {
                int maxHeaderLen = (space.phase == PacketPhase.APPLICATION) ? QuicFrameBuilder.MAX_SHORT_HEADER_LENGTH : QuicFrameBuilder.MAX_LONG_HEADER_LENGTH;
                int remaining = (int) connectionMetadata.clientMetadata.maxUdpPayloadSize - GCM_TAG_LENGTH - maxHeaderLen;

                logger.error("Strange overflow UDP max {} pack lim {} payload reminder {} (cap {}), frame size {} (send sum: {}, init start {})",
                        connectionMetadata.clientMetadata.maxUdpPayloadSize, remaining, reminder, payload.buf().capacity(), frame.data().buf().remaining(),
                        framesToSendSumLen, start);
                throw e;
            }
            frame.data().release();
        } //coalescing

        payload.buf().limit(payload.buf().position());
        payload.buf().position(start);
        framesToSendSumLen = 0;

        return makePacket(currentTimestamp, dest, payload, ackEliciting);
    }

    public DatagramToSend makeDatagram(long currentTimestamp, InetSocketAddress dest, PoolBuffer payload, boolean ackEliciting) {
        return new DatagramToSend(PacketSource.NEW,
                makePacket(currentTimestamp, dest, payload, ackEliciting),
                ectMarking,
                dest
                );
    }

    private PoolBuffer makePacket(long currentTimestamp, InetSocketAddress dest, PoolBuffer payload, boolean ackEliciting) {
        PoolBuffer datagram = writeBufferPool.requestWriteBuffer();
        try {
            long packetNumber = space.allocatePacketNumber();

            switch (space.phase) {
                case INITIAL -> QuicPacketBuilder.buildInitialPacket(
                        connectionMetadata.quicVersion,
                        datagram,
                        connectionMetadata.clientCid,   // DCID = connection ID
                        connectionIdBytes,              // SCID = connection ID (server uses same)
                        packetNumber,
                        space.getLargestAckedPacketNumber(),
                        payload.buf().duplicate(),      // Plaintext payload
                        connectionMetadata.serverInitialCrypto.get(connectionMetadata.quicVersion)
                );
                case HANDSHAKE -> QuicPacketBuilder.buildHandshakePacket(
                        connectionMetadata.quicVersion,
                        datagram,
                        connectionMetadata.clientCid,   // DCID = connection ID
                        connectionIdBytes,              // SCID = connection ID (server uses same)
                        packetNumber,
                        space.getLargestAckedPacketNumber(),
                        payload.buf().duplicate(),      // Plaintext payload
                        connectionMetadata.serverHandshakeCrypto
                );
                case APPLICATION -> QuicPacketBuilder.build1RttPacket(
                        connectionMetadata.quicVersion,
                        datagram,
                        connectionMetadata.clientCid,
                        packetNumber,
                        space.getLargestAckedPacketNumber(),
                        payload.buf().duplicate(),       // Plaintext payload
                        connectionMetadata.serverApplicationCrypto,
                        connectionMetadata.currentPhase
                );
            }

            space.onPacketSent(currentTimestamp, packetNumber, payload, ackEliciting, dest);
            return datagram;
        } catch (QuicException e) {
            datagram.release();
            payload.release();
            logger.error("Failed to build packet", e);
        }
        return null;
    }
}
