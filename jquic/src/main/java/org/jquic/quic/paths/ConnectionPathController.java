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
import org.jquic.quic.crypto.QuicCrypto;
import org.jquic.quic.linux.ECT;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.SocketAddress;
import java.util.*;
import java.util.stream.Collectors;

import static org.jquic.quic.paths.PathState.*;

public class ConnectionPathController {
    public static final int MAX_PATH_ID = 3;
    public static final int PROBING_TIMEOUT = 1000;
    public static final int PATH_DEAD_TIMEOUT = 5000;
    public static final int VERIFICATION_TIMEOUT = 30000;
    private final QuicConnection connection;
    private final Map<SocketAddress, ConnectionPath> pathMap = new HashMap<>();
    private final Deque<DatagramBuilder.DatagramToSend> outboundQueue = new ArrayDeque<>();
    private final Deque<DatagramBuilder.DatagramToSend> ackOutboundQueue = new ArrayDeque<>();
    private SocketAddress primaryAddress;
    private final static Logger logger = LoggerFactory.getLogger(ConnectionPathController.class);

    public  ConnectionPathController(QuicConnection connection, SocketAddress primaryAddress) {
        this.connection = connection;
        this.primaryAddress = primaryAddress;
        DatagramBuilder datagramBuilder = new DatagramBuilder(
                connection.connectionIdBytes, connection.getBufferPool(), this,
                (connection.getCongestionControl() != null) ? connection.getCongestionControl().getEctMarking() : ECT.ECT_0,
                primaryAddress, connection.connectionMetadata);
        pathMap.put(primaryAddress, new ConnectionPath(primaryAddress, connection.getCurrentTimestamp(), datagramBuilder));
    }

    public void sendPacket(long currentTimestamp, PoolBuffer payload, PacketNumberSpace space, boolean isAck) {
        pathMap.get(primaryAddress).datagramBuilder.sendPacket(currentTimestamp, payload, space, isAck);
    }

    public SocketAddress getRemoteAddress() {
        return primaryAddress;
    }

    public void onConnectionEstablished() {
        if (pathMap.containsKey(primaryAddress)) {
            pathMap.get(primaryAddress).state = VERIFIED;
        }
    }

    public void onChallenge(SocketAddress address, byte[] challengeData) {
        ConnectionPath path = pathMap.get(address);
        if (path != null && path.state == NEW && Arrays.equals(path.challenge, challengeData)) {
            path.state = VERIFIED;
            path.challenge = null;
            logger.info("New Sender address VERIFIED for CID {}: {}", connection.getConnectionId(), address);
        }
    }

    public void appendPacket(DatagramBuilder.DatagramToSend outboundPacket, boolean hasAck) {
        if (hasAck) {
            ackOutboundQueue.offer(outboundPacket);
        } else {
            outboundQueue.offer(outboundPacket);
        }
    }

    /**
     * Polls one outbound packet from the connection's outbound queue.
     * The owning {@code SelectorThread} calls this after every processing cycle
     * to drain any packets that were produced internally (early-1RTT replay,
     * send1RttPacket, etc.) and send them to the {@code DatagramChannel}.
     *
     * @return the next ready-to-send encrypted packet, or {@code null} if the queue is empty
     */
    public OutboundPacket pollOutbound() {
        OutboundPacket probePacket = checkConnectionPaths();
        if (probePacket != null) return probePacket;

        DatagramBuilder.DatagramToSend outboundPacket = getOutboundDatagram(ackOutboundQueue); // Give priority to acks
        if (outboundPacket == null) {
            outboundPacket = getOutboundDatagram(outboundQueue);
        }

        if (outboundPacket != null) {

            DatagramBuilder.PacketToSend packetToSend;
            while ( (packetToSend = outboundPacket.linkedPackets().poll()) != null) {
                if ( (connection.getPeerState() == QuicConnection.State.ESTABLISHED && (packetToSend.space().phase == PacketNumberSpace.PacketPhase.INITIAL || packetToSend.space().phase == PacketNumberSpace.PacketPhase.HANDSHAKE)) ||
                     (connection.getPeerState() == QuicConnection.State.HANDSHAKE && packetToSend.space().phase == PacketNumberSpace.PacketPhase.INITIAL) ) {
                    packetToSend.payload().release();
                } else {
                    packetToSend.space().onPacketSent(packetToSend.timestamp(), packetToSend.packetNumber(), packetToSend.payload(), packetToSend.ackEliciting());
                }
            }
            return new OutboundPacket(outboundPacket.packetSource(), outboundPacket.data(), outboundPacket.ectMarking(), outboundPacket.dest());
        }
        return null;
    }

    private DatagramBuilder.DatagramToSend getOutboundDatagram(Deque<DatagramBuilder.DatagramToSend> queue) {
        DatagramBuilder.DatagramToSend datagram = queue.peek();
        if (datagram == null) {
            pathMap.values().forEach(f -> f.datagramBuilder.flushPacket());
        }

        datagram = queue.peek();
        if (datagram == null) {
            return null;
        }

        if (pathMap.isEmpty()) {
            return null;
        }

        ConnectionPath path = pathMap.get(primaryAddress);
        Iterator<ConnectionPath> iterator = pathMap.values().iterator();

        while (path == null || (path.state == NEW && path.receivedBytes * 3 < path.sentBytes + datagram.data().buf().remaining()) ) { // 3X Amplification limit
            if (path!= null && path.bytesLastBlocked != path.receivedBytes) {
                logger.info("Blocked by amplification limit received: {} sent {} packet {}", path.receivedBytes, path.sentBytes, datagram.data().buf().remaining());
                path.bytesLastBlocked = path.receivedBytes;
            }
            if (iterator.hasNext()) {
                path = iterator.next();
            } else {
                path = null;
                break;
            }
        }

        if (path != null) {
            path.sentBytes += datagram.data().buf().remaining();
            logger.info("Sending more bytes: {} total sent: {}", datagram.data().buf().remaining(), path.sentBytes);
            queue.pollFirst();
            return new DatagramBuilder.DatagramToSend(datagram.packetSource(), datagram.data(), datagram.ectMarking(), path.address, datagram.linkedPackets());
        }

        return null;
    }

    public void updateIncomingLimits(SocketAddress sender, int packetLen) {
        ConnectionPath path = pathMap.get(sender);
        if (path != null) {
            path.receivedBytes += packetLen;
            path.lastActive = connection.getCurrentTimestamp();
            logger.debug("Received more bytes: {} total received: {}", packetLen, path.receivedBytes);
        } else {
            logger.info("Sender unknown: {} current peers {}", sender, pathMap.keySet().stream().map(Object::toString).collect(Collectors.joining(", ")));
        }
    }

    public @Nullable OutboundPacket checkConnectionPaths() {
        for (Iterator<Map.Entry<SocketAddress, ConnectionPath>> it = pathMap.entrySet().iterator(); it.hasNext(); ) {
            ConnectionPath path = it.next().getValue();
            if (path.state == VERIFIED && !path.address.equals(primaryAddress)) {
                if (connection.getCurrentTimestamp() - path.lastActive > PROBING_TIMEOUT) {
                    path.state = PROBING;
                    logger.info("Probing dangling path (connection {} path {})", connection.getConnectionId(), path.address);
                    path.probeSentAt = connection.getCurrentTimestamp();
                    path.datagramBuilder.sendPing(connection.getApplicationSpace());
                }
            }
            if (path.state == PROBING) {
                if (connection.getCurrentTimestamp() - path.lastActive < PROBING_TIMEOUT) {
                    path.state = VERIFIED;
                } else if (connection.getCurrentTimestamp() - path.lastActive > PATH_DEAD_TIMEOUT) {
                    it.remove();
                    logger.info("Dangling path declared dead (connection {} path {})", connection.getConnectionId(), path.address);
                } else if (connection.getCurrentTimestamp() - path.probeSentAt > PROBING_TIMEOUT) {
                    path.probeSentAt = connection.getCurrentTimestamp();
                    path.datagramBuilder.sendPing(connection.getApplicationSpace());
                }
            }
            if (path.state == NEW && connection.getCurrentTimestamp() - path.createdAt > VERIFICATION_TIMEOUT) {
                logger.info("Path removed UNVERIFIED Connection#{}, path {}", connection.getConnectionId(), path.address);
                it.remove(); // Not verified yet.
            }
        }
        return null;
    }

    public boolean checkSenderAddress(SocketAddress sender, int packetSize) {
        if (sender == null) sender = primaryAddress;

        if (!pathMap.containsKey(sender)) {
            logger.error("New Sender address not found for CID {}: {}", connection.getConnectionId(), sender);
            if (pathMap.size() >= MAX_PATH_ID) {
                connection.closeConnection(QuicTransportError.PROTOCOL_VIOLATION, "Too many active paths for CID: " + connection.getConnectionId());
                return false;
            }
            ConnectionPath currentPath = pathMap.get(primaryAddress);
            if (currentPath != null) {
                currentPath.datagramBuilder.flushPacket();
            }
            DatagramBuilder datagramBuilder = new DatagramBuilder(
                    connection.connectionIdBytes, connection.getBufferPool(), this,
                    (connection.getCongestionControl() != null) ? connection.getCongestionControl().getEctMarking() : ECT.ECT_0,
                    sender, connection.connectionMetadata);
            ConnectionPath path = new ConnectionPath(sender, connection.getCurrentTimestamp(), datagramBuilder);
            path.receivedBytes += packetSize;
            pathMap.put(sender, path);
            PoolBuffer buf = connection.getBufferPool().requestWriteBuffer();
            path.challenge = new byte[8];
            QuicCrypto.secureRandom.get().nextBytes(path.challenge);
            QuicFrameBuilder.writePathChallengeFrame(buf.buf(), path.challenge);
            connection.send1RttPacket(buf); // Send Path Challenge
            primaryAddress = sender;
        }
        return true;
    }

    public int outboundQueueSize() {
        return outboundQueue.size() + ackOutboundQueue.size();
    }

    public void clear() {
        for (Map.Entry<SocketAddress, ConnectionPath> entry : pathMap.entrySet()) {
            entry.getValue().datagramBuilder.flushPacket();
        }
        pathMap.clear();

        for (DatagramBuilder.DatagramToSend datagram : ackOutboundQueue) {
            datagram.data().release();
            for (DatagramBuilder.PacketToSend packet : datagram.linkedPackets()) {
                packet.payload().release();
            }
        }
        ackOutboundQueue.clear();
        for (DatagramBuilder.DatagramToSend datagram : outboundQueue) {
            datagram.data().release();
            for (DatagramBuilder.PacketToSend packet : datagram.linkedPackets()) {
                packet.payload().release();
            }
        }
        outboundQueue.clear();
    }
}
