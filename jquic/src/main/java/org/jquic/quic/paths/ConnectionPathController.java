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

import org.jquic.quic.QuicConnection;
import org.jquic.quic.QuicFrameBuilder;
import org.jquic.quic.QuicTransportError;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.crypto.QuicCrypto;
import org.jquic.quic.linux.ECT;
import org.jquic.quic.packets.PacketNumberSpace;
import org.jquic.quic.packets.PacketPhase;
import org.jquic.quic.packets.WindowedStatCounter;
import org.jquic.quic.streamapi.CongestionControl;
import org.jquic.quic.streamapi.congestion.TcpPrague;
import org.jquic.quic.streamapi.impl.ApplicationData;
import org.jquic.quic.struct.TimeoutHeap;
import org.jquic.quic.struct.TriStateQueue;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.*;
import java.util.stream.Collectors;

import static org.jquic.quic.paths.PathState.*;

public class ConnectionPathController implements TimeoutHeap.Entry {
    public static final int MAX_PATH_ID = 3;
    public static final int PROBING_TIMEOUT = 1000;
    public static final int PATH_DEAD_TIMEOUT = 5000;
    public static final int VERIFICATION_TIMEOUT = 45000;
    private static final CongestionControl INITAL_CC = new TcpPrague();
    private final QuicConnection connection;
    private final Map<SocketAddress, ConnectionPath> pathMap = new HashMap<>();

    private final ArrayDeque<UrgentFrame> urgentQueue = new ArrayDeque<>();

    private final CombinedQueue initQueue = new CombinedQueue();
    private final CombinedQueue handshakeQueue = new CombinedQueue();
    private final CombinedQueue applicationQueue = new CombinedQueue();

    private final DatagramBuilder initDatagramBuilder;
    private final DatagramBuilder handshakeDatagramBuilder;
    private final DatagramBuilder applicationDatagramBuilder;

    private InetSocketAddress primaryAddress;
    private long nextShedNs = 0;
    private final static Logger logger = LoggerFactory.getLogger(ConnectionPathController.class);

    private CongestionControl congestionControl;
    private boolean hasAmpBlock = false;

    private PacketNumberSpace pnSpace(PacketPhase phase) {
        return switch (phase) {
            case INITIAL -> connection.getInitialSpace();
            case HANDSHAKE -> connection.getHandshakeSpace();
            case APPLICATION -> connection.getApplicationSpace();
        };
    }

    public  ConnectionPathController(QuicConnection connection, InetSocketAddress primaryAddress) {
        this.connection = connection;
        this.primaryAddress = primaryAddress;

        initDatagramBuilder = getDatagramBuilder(PacketPhase.INITIAL);
        handshakeDatagramBuilder = getDatagramBuilder(PacketPhase.HANDSHAKE);
        applicationDatagramBuilder = getDatagramBuilder(PacketPhase.APPLICATION);

        initQueue.setReadyToPoll(true);
        handshakeQueue.setReadyToPoll(true);

        pathMap.put(primaryAddress, new ConnectionPath(primaryAddress, connection.getCurrentTimestamp(), 32));
    }
    
    public ConnectionPath getConnectionPath(SocketAddress socketAddress) {
        return pathMap.get(socketAddress);
    }

    public long getSmoothedRtt() {
        ConnectionPath path = getDefaultPath();
        if (path == null) return 333;
        return path.windowedStatCounter.getSmoothedRtt();
    }

    public long getPto() {
        ConnectionPath path = getDefaultPath();
        if (path == null) return 999;
        return path.windowedStatCounter.getPTO();
    }

    private @Nullable ConnectionPath getDefaultPath() {
        ConnectionPath path = pathMap.get(primaryAddress);
        if (path == null) path = pathMap.values().stream().filter(m -> m.state == VERIFIED).findFirst().orElse(null);
        if (path == null) path = pathMap.values().stream().findAny().orElse(null);
        return path;
    }

    public void setCongestionControl(CongestionControl congestionControl) {
        if (congestionControl != null) {
            this.congestionControl = congestionControl;
            applicationDatagramBuilder.setEct(congestionControl.getEctMarking());
            initDatagramBuilder.setEct(congestionControl.getEctMarking());
            handshakeDatagramBuilder.setEct(congestionControl.getEctMarking());
            for (ConnectionPath path : pathMap.values()) {
                path.congestionControl = congestionControl;
                path.windowedStatCounter.setTimeWindowMs(path.congestionControl.timeWindowMs());
            }
        }
    }

    private DatagramBuilder getDatagramBuilder(PacketPhase phase) {
        ECT ect = congestionControl != null ?
                congestionControl.getEctMarking() : ECT.ECT_1;
        return new DatagramBuilder(connection.connectionIdBytes, connection.getBufferPool(),
                ect, connection.connectionMetadata, pnSpace(phase));
    }

    public void onAckRecieved(SocketAddress sender, int bytesAcked) {
        pathMap.get(sender).bytesAcked += bytesAcked;
    }

    private CombinedQueue getQueue(PacketPhase phase) {
        return switch (phase) {
            case INITIAL -> initQueue;
            case HANDSHAKE -> handshakeQueue;
            case APPLICATION -> applicationQueue;
        };
    }

    public boolean sendFrame(PoolBuffer payload, PacketPhase phase) {
        return getQueue(phase).addFrame(new Frame(payload, phase, true));
    }
    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public boolean sendAck(PoolBuffer payload, PacketPhase phase) {
        return getQueue(phase).addAck(new Frame(payload, phase, false));
    }
    public boolean sendRetransmit(PoolBuffer payload, PacketPhase phase) {
        return getQueue(phase).addRetransmit(new Frame(payload, phase, true));
    }
    public void appendsAppData(TriStateQueue<ApplicationData> queue) {
        applicationQueue.addApplication(queue);
    }

    public long getNextShedNs() {
        return nextShedNs;
    }

    public InetSocketAddress getRemoteAddress() {
        return primaryAddress;
    }

    public void onConnectionEstablished() {
        applicationQueue.setReadyToPoll(true);
        if (pathMap.containsKey(primaryAddress)) {
            pathMap.get(primaryAddress).state = VERIFIED;
        }
    }

    public void onPathChallengeResponse(SocketAddress address, byte[] challengeData) {
        ConnectionPath path = pathMap.get(address);
        if (path != null && path.state == NEW && Arrays.equals(path.challenge, challengeData)) {
            path.state = VERIFIED;
            path.challenge = null;
            logger.info("New Sender address VERIFIED for CID {}: {}", connection.getConnectionId(), address);
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
    public DatagramToSend pollOutbound(long currentTimeMs, long currentNanos) {
//        checkConnectionPaths();
        return getOutboundDatagram(currentTimeMs, currentNanos);
    }

    private DatagramToSend getOutboundDatagram(long currentTimeMs, long currentNanos) {
        if (pathMap.isEmpty()) {
            nextShedNs = currentNanos + 1000_000;
            return null;
        }

        UrgentFrame frame = urgentQueue.poll();
        if (frame != null) {
            ConnectionPath path = pathMap.get(frame.dest());
            if (path != null) {
                DatagramToSend datagram = switch (frame.phase()) {
                    case INITIAL -> initDatagramBuilder.makeDatagram(currentTimeMs, path.address, frame.data(), frame.ackEliciting());
                    case HANDSHAKE -> handshakeDatagramBuilder.makeDatagram(currentTimeMs, path.address, frame.data(), frame.ackEliciting());
                    case APPLICATION -> applicationDatagramBuilder.makeDatagram(currentTimeMs, path.address, frame.data(), frame.ackEliciting());
                };
                if (datagram.data() == null) {
                    logger.error("Could not make datagram for frame phase {} in pahse {} to {}", frame.phase(), curPhase(), path);
                    return null;
                } else{
                    logger.info("Sending Urgent frame to {} {} bytes", frame.dest(), datagram.data().buf().remaining());
                }
                if (!urgentQueue.isEmpty()) {
                    nextShedNs = currentTimeMs;
                }
//                setNextShedNs(currentNanos);
                return datagram;
            }
        }

        ConnectionPath path = pathMap.get(primaryAddress);
        if (path == null || isAmplificationBlock(path)) {
            hasAmpBlock = path != null;
            path = null;
            for (ConnectionPath path1 : pathMap.values()) {
                if (!isAmplificationBlock(path1) && path1.state != PROBING) {
                    path = path1;
                    break;
                }
            }
        }

        if (path != null) {
            if (path.nextSendSchedNs > currentNanos) {
                nextShedNs = path.nextSendSchedNs;
                return null;
            }

            if (path.nextSendSchedNs == 0) {
                schedNextDatagram(path, currentTimeMs, currentNanos);
                path.nextSendSchedNs = currentNanos;
            }
            if (path.nextDatagram == null) {
                schedNextDatagram(path, currentTimeMs, currentNanos);
            }

            if (path.nextDatagram != null) {
                path.sentBytes += path.nextDatagram.data().buf().remaining();
                if (logger.isDebugEnabled()) {
                    logger.debug("Sending more bytes: {} total sent: {}", path.nextDatagram.data().buf().remaining(), path.sentBytes);
                }
                DatagramToSend outboundPacket = path.nextDatagram;

                path.nextDatagram = null;

                schedNextDatagram(path, currentTimeMs, currentNanos);

                return outboundPacket;
            } else {
                schedNextDatagram(path, currentTimeMs, currentNanos);
            }

            if (path.nextSendSchedNs < currentNanos) { path.nextSendSchedNs = currentNanos; } // Do not let the schedule fall back too late.
        }

        nextShedNs = currentNanos + 1000;
        return null;
    }

    private int getMaxPacketSize(ConnectionPath path) {
        long defaultMax = connection.connectionMetadata.clientMetadata != null ?
                connection.connectionMetadata.clientMetadata.maxUdpPayloadSize : 1200;
        return path.state == NEW ?
                (int) Math.min(hasAmpBlock ? 200 : defaultMax, path.receivedBytes * 3 - path.sentBytes)
                : (int) defaultMax;
    }

    private void schedNextDatagram(ConnectionPath path, long currentTimeMs, long currentTimeNs) {
        QuicConnection.State peerState = connection.getPeerState();
        QuicConnection.State state = connection.getState();
        if ( path.nextDatagram == null && peerState == QuicConnection.State.INITIAL ) path.nextDatagram = initDatagramBuilder.getPacket(currentTimeMs, path.address, true, getMaxPacketSize(path), initQueue);
        if ( path.nextDatagram == null &&
                ( (peerState == QuicConnection.State.INITIAL && state == QuicConnection.State.HANDSHAKE)
                || peerState == QuicConnection.State.HANDSHAKE) ) path.nextDatagram = handshakeDatagramBuilder.getPacket(currentTimeMs, path.address, true, getMaxPacketSize(path), handshakeQueue);
        if ( path.nextDatagram == null &&
                ( (peerState == QuicConnection.State.HANDSHAKE && state == QuicConnection.State.ESTABLISHED)
                || peerState == QuicConnection.State.ESTABLISHED)) path.nextDatagram = applicationDatagramBuilder.getPacket(currentTimeMs, path.address, true, getMaxPacketSize(path), applicationQueue);

        if (path.nextDatagram == null) {
            return;
        }

        long delay = getCongestionDelay(currentTimeNs, currentTimeMs, path);

        path.nextSendSchedNs += delay;
        nextShedNs = path.nextSendSchedNs;
    }

    private boolean isAmplificationBlock(ConnectionPath path) {
        if (path.nextDatagram == null) return false;
        if (path.state == NEW && path.receivedBytes * 3 < path.sentBytes + path.nextDatagram.data().buf().remaining()) {
            if (path.bytesLastBlocked != path.receivedBytes) {
                logger.info("Blocked by amplification limit received: {} sent {} packet {}", path.receivedBytes, path.sentBytes, path.nextDatagram.data().buf().remaining());
                path.bytesLastBlocked = path.receivedBytes;
            }
            return true;
        }
        return false;
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

    public PacketPhase curPhase() {
        return switch (connection.getPeerState()) {
            case INITIAL -> PacketPhase.INITIAL;
            case HANDSHAKE -> PacketPhase.HANDSHAKE;
            case ESTABLISHED ->  PacketPhase.APPLICATION;
            case CLOSING -> null;
            case CLOSED -> null;
        };
    }

    public void checkConnectionPaths() {
        for (Iterator<Map.Entry<SocketAddress, ConnectionPath>> it = pathMap.entrySet().iterator(); it.hasNext(); ) {
            ConnectionPath path = it.next().getValue();
            if (path.state == VERIFIED && !path.address.equals(primaryAddress)) {
                if (connection.getCurrentTimestamp() - path.lastActive > PROBING_TIMEOUT) {
                    path.state = PROBING;
                    logger.info("Probing dangling path (connection {} path {})", connection.getConnectionId(), path.address);
                    path.probeSentAt = connection.getCurrentTimestamp();
                    sendPing(path.address);
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
                    sendPing(path.address);
                }
            }
            if (path.state == NEW
                    && connection.getCurrentTimestamp() - path.lastActive > PROBING_TIMEOUT
                    && connection.getCurrentTimestamp() - path.probeSentAt > PROBING_TIMEOUT
            ) {
                path.probeSentAt = connection.getCurrentTimestamp();
                sendPing(path.address);
            }
            if (path.state == NEW && connection.getCurrentTimestamp() - path.createdAt > VERIFICATION_TIMEOUT) {
                logger.info("Path removed UNVERIFIED Connection#{}, path {}", connection.getConnectionId(), path.address);
                it.remove(); // Not verified yet.
            }
        }
    }

    public void sendPing(InetSocketAddress address) {
        PoolBuffer poolBuffer = connection.getBufferPool().requestWriteBuffer();
        QuicFrameBuilder.writePingFrame(poolBuffer);
        sendUrgentFrame(poolBuffer, true, address);
    }

    public void sendUrgentFrame(PoolBuffer poolBuffer, boolean ackEliciting, InetSocketAddress dest) {
        urgentQueue.offer(new UrgentFrame(poolBuffer, curPhase(), ackEliciting, dest));
    }

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public boolean checkSenderAddress(InetSocketAddress sender, int packetSize) {
        if (sender == null) sender = primaryAddress;

        if (!pathMap.containsKey(sender)) {
            logger.info("New Sender address not found for CID {}: {}", connection.getConnectionId(), sender);
            if (pathMap.size() >= MAX_PATH_ID) {
                connection.closeConnection(QuicTransportError.PROTOCOL_VIOLATION, "Too many active paths for CID: " + connection.getConnectionId());
                return false;
            }

            ConnectionPath path = new ConnectionPath(sender, connection.getCurrentTimestamp(), 
                    congestionControl != null ? congestionControl.timeWindowMs() : 32);
            path.receivedBytes += packetSize;
            pathMap.put(sender, path);
            PoolBuffer buf = connection.getBufferPool().requestWriteBuffer();
            path.challenge = new byte[8];
            QuicCrypto.secureRandom.get().nextBytes(path.challenge);
            QuicFrameBuilder.writePathChallengeFrame(buf.buf(), path.challenge);
            sendUrgentFrame(buf, true, sender); // Send Path Challenge
            primaryAddress = sender;
        }
        return true;
    }

    public void clear() {
        pathMap.clear();

        initQueue.clear();
        handshakeQueue.clear();
        applicationQueue.clear();

        initDatagramBuilder.clear();
        handshakeDatagramBuilder.clear();
        applicationDatagramBuilder.clear();
    }

    public void clearOlderStats(long timestampMs) {
        for (ConnectionPath path : pathMap.values()) {
            path.windowedStatCounter.clearOldTimeBuckets(timestampMs);
        }
    }

    private int index = -1;

    @Override
    public int getTimeoutHeapIndex() {
        return index;
    }

    @Override
    public void setTimeoutHeapIndex(int idx) {
        index = idx;
    }

    @Override
    public long getTimeoutTimestamp() {
        return nextShedNs;
    }

    private long getCongestionDelay(long currentTimeNs, long currentTimeMs, ConnectionPath path) {
        CongestionControl congestionControl = path.congestionControl != null ? path.congestionControl : INITAL_CC;
        WindowedStatCounter windowedStatCounter = path.windowedStatCounter;
        return congestionControl.getDelay(
                currentTimeNs, currentTimeMs,
                1200,
                connection.getConnectionId(),
                windowedStatCounter.getSmoothedRtt(),
                windowedStatCounter.getLatestRtt(),
                windowedStatCounter.getMinRtt(),
                windowedStatCounter.getBytesAckedInLastRtt(),
                windowedStatCounter.getBytesLostInLastRtt(),
                windowedStatCounter.getBytesAcked(),
                windowedStatCounter.getBytesLost(),
                windowedStatCounter.getPacketsAcked(),
                windowedStatCounter.getLossTime(),
                windowedStatCounter.getLastAckTime(),
                windowedStatCounter.totalInFlightBytes(),
                10000,
                0,
                windowedStatCounter.getServerCeCounter(),
                windowedStatCounter.getIntervalCePackets()
        );
    }
}
