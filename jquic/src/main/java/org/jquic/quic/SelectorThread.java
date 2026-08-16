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

import org.jctools.queues.MessagePassingQueue;
import org.jctools.queues.MpscArrayQueue;
import org.jctools.queues.SpscArrayQueue;
import org.jctools.queues.SpscLinkedQueue;
import org.jquic.quic.buffers.BufferPool;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.linux.BpfRouting;
import org.jquic.quic.linux.ECT;
import org.jquic.quic.streamapi.impl.ApplicationData;
import org.jquic.quic.struct.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

// =========================================================================
// SELECTOR THREAD LOGIC
// =========================================================================
public class SelectorThread extends Thread {
    private static final Logger logger = LoggerFactory.getLogger(SelectorThread.class);
    public static final int OUTBOUND_APP_QUEUE_SIZE = QuicProperties.OUTBOUND_APP_QUEUE_SIZE;
    public static final int HANDSHAKE_QUEUE_CAP = QuicProperties.HANDSHAKE_QUEUE_CAP;
    public static final int MAX_RECIEVE_BATCH = QuicProperties.MAX_RECIEVE_BATCH;
    public static final int MAX_SEND_BATCH = QuicProperties.MAX_SEND_BATCH;

    private final int threadId;
    private QuicDatagramChannel channel;
    private final DatagramChannel socket;
    private final SpscLinkedQueue<PacketData> forwardedPackets;
    private final SpscArrayQueue<HandshakeTask> handshakeQueue = new SpscArrayQueue<>(HANDSHAKE_QUEUE_CAP);
    private final MessagePassingQueue<TriStateQueue<ApplicationData>> applicationWakeQueue = new MpscArrayQueue<>(OUTBOUND_APP_QUEUE_SIZE);
    private final AppDataPriorityQueue appDataPriorityQueue = new AppDataPriorityQueue();
    private final ConcurrentHashMap<Long, Integer> cidToSelectorMap;
    private final Map<Long, QuicConnection> activeConnections;
    private final Map<ByteBuffer, QuicConnection> initializingConnections = new HashMap<>();

    private final BufferPool bufferPool = new BufferPool();
    private final TimerWheelScheduler timerWheelScheduler = new TimerWheelScheduler(System.nanoTime());

    // Timeout management: PriorityQueue ordered by timeout timestamp
    private final TimeoutHeap<QuicConnection> timeoutHeap = new TimeoutHeap<>(QuicConnection.class);
    private long lastTimeoutCheck = System.currentTimeMillis();
    private static final long TIMEOUT_CHECK_INTERVAL_MS = QuicProperties.TIMEOUT_CHECK_INTERVAL_MS; // Check every second
    private int idleCounter = 0;
    private long startIdlingTimeMs = 0;
    private long tickTimeEmaNs = 0;

    private LinkedList<PacketToSend> packetsToSendPerConnection = new LinkedList<>();
    private long sentPackets;
    private long retransmittedPackets;
    private long receivedPackets;
    private double retransmitRateEma = 0.0;

    public BufferPool getBufferPool() {
        return bufferPool;
    }

    public record PacketToSend(SocketAddress socketAddress, PoolBuffer poolBuffer, ECT ectMarking) {}

    /**
     * Encapsulates a packet with its sender address for forwarding between threads.
     */
    private static class PacketData {
        final PoolBuffer buffer;
        final SocketAddress sender;

        PacketData(PoolBuffer buffer, SocketAddress sender) {
            this.buffer = buffer;
            this.sender = sender;
        }
    }

    public SelectorThread(int threadId, DatagramChannel socket, ConcurrentHashMap<Long, Integer> cidToSelectorMap, String name) throws IOException, NoSuchFieldException, IllegalAccessException {
        super(name);
        this.threadId = threadId;
        this.socket = socket;
        this.forwardedPackets = new SpscLinkedQueue<>();
        this.cidToSelectorMap = cidToSelectorMap;
        this.activeConnections = new HashMap<>();
    }

    public int getActiveConnectionCount() {
        return activeConnections.size();
    }

    public long getTickTimeEmaNs() {
        return tickTimeEmaNs;
    }

    public double getRetransmitRateEma() {
        return retransmitRateEma;
    }

    public int[] bufferStats() {
        return new int[]{ bufferPool.readBufferSize(), bufferPool.writeBufferSize() };
    }

    /**
     * Forwards a packet received by AcceptorThread to this Selector.
     * This is used when a short header packet arrives with an unknown CID.
     * Zero-copy implementation: takes ownership of the ByteBuffer.
     * The buffer will be returned to the pool after processing.
     */
    public void forwardPacket(PoolBuffer packet, SocketAddress sender) {
        try {
            // Zero-copy: just transfer ownership through queue
            // BlockingQueue provides happens-before guarantee for thread-safe handoff
            forwardedPackets.offer(new PacketData(packet, sender));
        } catch (Exception e) {
            logger.error("Selector-{}: Error enqueueing forwarded packet", threadId, e);
        }
    }

    public void forwardHandshake(HandshakeTask task) {
        handshakeQueue.offer(task);
    }

    @Override
    public void run() {
        PoolBuffer[] readBuffers = new PoolBuffer[MAX_RECIEVE_BATCH];

        try {
            this.channel = new QuicDatagramChannel(socket);

            for (int i = 0; i < MAX_RECIEVE_BATCH; i++) {
                readBuffers[i] = bufferPool.requestReadBuffer();
            }

            long lastTime = System.nanoTime();
            while (!Thread.currentThread().isInterrupted()) {

                long nowNs = System.nanoTime();
                long now = System.currentTimeMillis();
                tickTimeEmaNs = tickTimeEmaNs * 4 / 5 + (nowNs - lastTime) / 5;
                if (sentPackets > 0) {
                    retransmitRateEma = retransmitRateEma * 0.8 + ( ((double) retransmittedPackets) / sentPackets) * 0.2;
                }

                lastTime = nowNs;
                retransmittedPackets = 0;
                sentPackets = 0;

                boolean hadWork = false;
                long recievedPacketsAtStart = receivedPackets;

                // Process packets from socket
                List<QuicDatagramChannel.ReceivedPacket> batch = (now - startIdlingTimeMs > 1_000) ?
                        channel.receiveBatchBlocking(readBuffers) :
                        channel.receiveBatch(readBuffers);

                for (int i = 0; i < batch.size(); i++) {
                    // Request fresh buffers
                    readBuffers[i] = bufferPool.requestReadBuffer();
                }

                if (!batch.isEmpty()) logger.info("Selector-{}: Received {} datagrams in batch", threadId, batch.size());

                for (QuicDatagramChannel.ReceivedPacket packet : batch) {
                    if (packet.sender() != null) {
                        processDatagram(now, packet.data().borrow(), packet.sender(), "socket", packet.ecnFlags());
                        hadWork = true;
                    }
                    packet.data().release();
                }

                if (receivedPackets != recievedPacketsAtStart) logger.info("Selector-{}: Processed {} packets from batch", threadId, (receivedPackets - recievedPacketsAtStart));

                long revPBeforeFwd = receivedPackets;
                // Process forwarded packets
                PacketData forwarded;
                while ((receivedPackets - recievedPacketsAtStart) < MAX_RECIEVE_BATCH && (forwarded = forwardedPackets.poll()) != null) {
                    processDatagram(now, forwarded.buffer, forwarded.sender, "forwarded", 0);
                    hadWork = true;
                }
                if (receivedPackets != revPBeforeFwd) logger.info("Selector-{}: Processed {} packets from forward", threadId, (receivedPackets - revPBeforeFwd));

                long revPBeforeHandshake = receivedPackets;
                // It looks we are not handling new connections if too busy...
                HandshakeTask handshakeTask;
                while ((receivedPackets - recievedPacketsAtStart) < MAX_RECIEVE_BATCH && (handshakeTask = handshakeQueue.poll()) != null) {
                    processHandshakeTask(now, nowNs, handshakeTask);
                    hadWork = true;
                }
                if (receivedPackets != revPBeforeHandshake)  logger.info("Selector-{}: Processed {} packets from Handshake", threadId, (receivedPackets - revPBeforeHandshake));

                ArrayList<TimerWheelScheduler.ScheduledEvent> recordsToProcess = timerWheelScheduler.getNewRecords(nowNs);

                for (TimerWheelScheduler.ScheduledEvent scheduledEvent : recordsToProcess) {
                    hadWork |= switch (scheduledEvent.eventType()) {
                        case LOSS_DETECTION -> retransmitPackagesInConnection(scheduledEvent, nowNs);
                    };
                }

                int currentSendQueueSize = packetsToSendPerConnection.size();

                applicationWakeQueue.drain(rec -> appDataPriorityQueue.add(rec, nowNs));

                int i = currentSendQueueSize;
                if (currentSendQueueSize != 0) logger.info("Selector-{}: Have {} response packets before taking application pkts", threadId, currentSendQueueSize);

                while (appDataPriorityQueue.nextTimestamp() < nowNs && i < MAX_RECIEVE_BATCH) {
                    ApplicationData data = appDataPriorityQueue.poll(nowNs);
                    processApplicationPacket(data, now);
                    i++;
                    hadWork = true;
                }

                sendAllCollectedPackets();

                // Check for timed out connections periodically
                if (now - lastTimeoutCheck > TIMEOUT_CHECK_INTERVAL_MS) {
                    evictTimedOutConnections(now);
                    lastTimeoutCheck = now;
                }

                if (!hadWork) {
                    if (idleCounter == 0) {
                        startIdlingTimeMs = now;
                    }
                    if (idleCounter > 100) {
                        Thread.yield();
                    }
                    idleCounter++;
                } else {
                    startIdlingTimeMs = now;
                    idleCounter = 0;
                }
            }
        } catch (Exception e) {
            logger.error("Selector-{}: Error in selector thread", threadId, e);
        } finally {
            for (PoolBuffer buffer : readBuffers) {
                buffer.release();
            }
        }
    }

    private void sendAllCollectedPackets() throws IOException {
        if (!packetsToSendPerConnection.isEmpty()) logger.info("Selector-{}: Senging {} response packets", threadId, packetsToSendPerConnection.size());
        try {
            List<PacketToSend> entries = packetsToSendPerConnection.subList(0, Math.min(packetsToSendPerConnection.size(), MAX_SEND_BATCH));
            while (!entries.isEmpty()) {
                int res = channel.sendBatch(entries);
                if (res < 0) {
                    throw new IOException("Error enqueueing application packets code: " + res);
                }
                entries = entries.subList(res, entries.size());
                sentPackets += res;
            }
        } finally {
            packetsToSendPerConnection.forEach(p->p.poolBuffer().release());
            packetsToSendPerConnection = new LinkedList<>();
        }
    }

    private boolean retransmitPackagesInConnection(TimerWheelScheduler.ScheduledEvent event, long nowNs) {
        QuicConnection conn = activeConnections.get(event.connectionId());
        if (conn != null) {
            conn.retransmitLostPackets();
            pollConnectionDataAndSend(conn);
            timerWheelScheduler.scheduleAt(nowNs + 1_000_000, event);
            return true;
        }
        return false;
    }

    private void pollConnectionDataAndSend(QuicConnection conn) {
        OutboundPacket outbound;
        while ((outbound = conn.getConnectionPathController().pollOutbound()) != null) {
            packetsToSendPerConnection.add(new PacketToSend(outbound.dest(), outbound.data(), outbound.ectMarking()));
            switch (outbound.packetSource()) {
                case NEW -> sentPackets++;
                case RETRANSMISSION -> retransmittedPackets++;
            }
        }
    }

    private void processApplicationPacket(ApplicationData appPacket, long now) {
        QuicConnection conn = appPacket.connection();
        logger.debug("Polled application data frame cid {}", conn.getConnectionId());
        conn.setCurrentTimestamp(now);

        conn.send1RttPacket(appPacket.data());
        // Update timeout in heap after processing
        timeoutHeap.insertOrUpdate(conn);

        if (conn.getConnectionPathController().outboundQueueSize() > 0) {
            logger.debug("Selector-{}: Connection CID: {} sending {} response packets.", threadId, conn.getConnectionId(), conn.getConnectionPathController().outboundQueueSize());
        }
        pollConnectionDataAndSend(conn);
    }

    /**
     * Processes a received datagram which may contain multiple coalesced packets.
     * Routes packets to appropriate connections based on CID.
     */
    private void processDatagram(long now, PoolBuffer datagram, SocketAddress sender, String source, int ecnFlags) {
        try {
            int datagramSize = datagram.buf().remaining();
            // Process all coalesced packets in the datagram
            while (datagram.buf().hasRemaining()) {
                if (datagram.buf().remaining() < 9) { // Minimum: 1 byte flags + 8 bytes CID
                    logger.debug("Selector-{}: Remaining bytes too short for packet: {}", 
                               threadId, datagram.buf().remaining());
                    break;
                }

                QuicPacketHeader.PacketSummary packetSummary = QuicPacketHeader.parseSummary(datagram.buf());

                if (packetSummary == null || packetSummary.type() == QuicPacketHeader.PacketType.RETRY) {
                    break; //invalid data skip remaining
                }

                if (packetSummary.type() != QuicPacketHeader.PacketType.ONE_RTT && packetSummary.version() == QuicVersion.UNKNOWN) {
                    logger.info("[Acceptor] Unsupported QUIC version. Sending Version Negotiation.");
                    // Send Version Negotiation: DCID = received SCID, SCID = received DCID

                    if (datagram.buf().remaining() >= 1200) { // Minimum packet size requirement
                        PoolBuffer vnPacket = QuicPacketBuilder.buildVersionNegotiationPacket(bufferPool, packetSummary.scid(), packetSummary.dcid());
                        try {
                            channel.send(vnPacket.buf(), sender, ECT.NONE);
                        } catch (Exception e) {
                            logger.error("Failed to send Version Negotiation packet", e);
                        }
                        vnPacket.release();
                    }
                    break;
                }

                receivedPackets++;
                logger.debug("Selector-{}: Packet datagram from {} for CID: {}, type: {}",
                           threadId, source, packetSummary.dcid(), packetSummary.type());

                ByteBuffer dcid = ByteBuffer.wrap(packetSummary.dcid());
                long cid = dcid.duplicate().getLong();

                // Look up connection
                QuicConnection connection = activeConnections.get(cid);
                if (connection == null) {
                    connection = initializingConnections.get(dcid);
                }

                if (packetSummary.type() == QuicPacketHeader.PacketType.ZERO_RTT ) {
                    logger.warn("Selector-{}: Processing {} packet for CID: {} not implemented",threadId, packetSummary.type(), cid);
                    skipPacket(datagram.buf());
                    continue;
                }

                if (connection == null) {
                    logger.warn("Selector-{}: No connection found for CID: {}, discarding datagram", threadId, cid);
                    cidToSelectorMap.remove(cid);
                    break;
                }

                if (!connection.getConnectionPathController().getRemoteAddress().equals(sender) && connection.getState() != QuicConnection.State.ESTABLISHED) {
                    //TODO: RETRY
                    logger.warn("Selector-{} CID: {}, different remote address, discarding datagram", threadId, cid);
                    break;
                }

                if (datagramSize > 0) {
                    connection.getConnectionPathController().updateIncomingLimits(sender, datagramSize);
                    datagramSize = 0;
                }

                // Route packet to connection for processing
                // Buffer position advances automatically as packet is read
                try {
                    connection.setCurrentTimestamp(now);

                    switch (packetSummary.type()) {
                        case INITIAL -> {
                            logger.debug("Selector-{}: Processing Initial packet for CID: {}", threadId, cid);
                            connection.processInitialAndRespond(datagram, ecnFlags);
                        }
                        case HANDSHAKE ->  { // Handshake packet (0b10)
                            logger.debug("Selector-{}: Processing Handshake packet for CID: {}", threadId, cid);
                            connection.processHandshakePacket(datagram, ecnFlags);
                        }
                        case ONE_RTT -> {
                            logger.debug("Selector-{}: Processing 1-RTT packet for CID: {} from: {}", threadId, cid, sender);
                            connection.process1RttPacket(datagram, ecnFlags, sender);
                        }
                        case RETRY, ZERO_RTT -> {
                            logger.warn("Selector-{}: Processing {} packet for CID: {} not implemented",threadId, packetSummary.type(), cid);
                            skipPacket(datagram.buf());
                        }
                    }
                    // Update timeout in heap after processing (remove-add pattern)
                    timeoutHeap.insertOrUpdate(connection);

                    // Drain any packets the connection produced internally (e.g. early-1RTT
                    // replay triggered by the ESTABLISHED transition, or sendFrame() calls).
                    logger.debug("Selector-{}: Connection CID: {} sending {} response packets.", threadId, cid, connection.getConnectionPathController().outboundQueueSize());

                    pollConnectionDataAndSend(connection);
                } catch (Exception e) {
                    logger.error("Selector-{}: Failed to process packet for CID: {}", threadId, cid, e);
                    break;
                }
            }
        } catch (Exception e) {
            logger.error("Selector-{}: Error processing datagram from {}", threadId, source, e);
        } finally {
            datagram.release();
        }
    }

    /**
     * Processes Initial packet from new connection.
     * Creates connection and sends Initial response (ServerHello).
     * Handshake will continue when client sends Handshake packet.
     */
    private void processHandshakeTask(long now, long nowNs,  HandshakeTask task) {
        try {
            logger.warn("Selector-{}: Processing Initial packet for new CID: {}", threadId, task.allocatedCid);

            QuicConnection connection = activeConnections.computeIfAbsent(task.allocatedCid,
                    _ -> {
                        QuicConnection conn = new QuicConnection(task.allocatedCid, task.packetSummary.version(), task.sender, applicationWakeQueue, this);
                        timeoutHeap.insertOrUpdate(conn);
                        timerWheelScheduler.scheduleAt(nowNs + 1_000_000L,
                                new TimerWheelScheduler.ScheduledEvent(TimerWheelScheduler.EventType.LOSS_DETECTION, task.allocatedCid));
                        return  conn;
                    });

            connection.setCurrentTimestamp(now);

            assignConnectionToSelector(connection.getConnectionId());

            ByteBuffer dcidKey = ByteBuffer.wrap(task.packetSummary.dcid());
            initializingConnections.put(dcidKey, connection);

            processDatagram(now, task.packet, task.sender, "initial", 0);

            initializingConnections.remove(dcidKey);

            // Register this selector as the owner of the connection
            logger.info("Selector-{}: Initial processed for CID: {}, first datagram processing finished",
                      threadId, task.allocatedCid);
        } catch (Exception e) {
            logger.error("Selector-{}: Initial packet processing error for CID: {}", threadId, task.allocatedCid, e);
        }
    }

    private void assignConnectionToSelector(long connectionId) {
        logger.info("Connection {} assigned to Selector {}", connectionId, threadId);

        // Update eBPF map if available
        try {
            BpfRouting.updateRouting(connectionId, threadId+1);
        } catch (Exception e) {
            logger.error("Failed to update eBPF map for connection {}", connectionId, e);
        }
    }

    /**
     * Evicts all connections that have exceeded their idle timeout.
     * Uses min-heap to efficiently find expired connections in O(k log n) where k = expired count.
     */
    private void evictTimedOutConnections(long now) {
        int evictedCount = 0;

        // Process expired connections from heap top
        while (!timeoutHeap.isEmpty()) {
            QuicConnection entry = timeoutHeap.peek();

            // Check if this connection has timed out
            if (entry.getTimeoutTimestamp() > now) {
                // All remaining connections are not yet timed out (min-heap property)
                break;
            }

            // Remove from heap
            QuicConnection connection = timeoutHeap.poll();

            logger.warn("Selector-{}: Connection CID: {} timed out at {}, evicting (now is: {})",
                       threadId, connection.getConnectionId(), connection.getTimeoutTimestamp(), now);
            evictConnection(connection.getConnectionId());
            evictedCount++;
        }

        if (evictedCount > 0) {
            logger.info("Selector-{}: Evicted {} timed out connection(s)", threadId, evictedCount);
        }
    }

    /**
     * Evicts a connection from active connections and removes it from the eBPF routing table.
     * Called when CONNECTION_CLOSE is received or connection times out.
     * 
     * @param connectionId The connection ID to evict
     */
    private void evictConnection(long connectionId) {
        try {

            // Remove from active connections
            QuicConnection removed = activeConnections.remove(connectionId);

            if (removed != null) {
                logger.info("Selector-{}: Evicted connection CID: {} from activeConnections", 
                          threadId, connectionId);

                // Update connection state to CLOSED
                removed.setState(QuicConnection.State.CLOSED);
                timeoutHeap.remove(removed);
            }


            // Remove from CID-to-Selector mapping
            cidToSelectorMap.remove(connectionId);

            // Remove from eBPF map
            try {
                BpfRouting.evictRoute(connectionId);
                logger.info("Selector-{}: Removed CID: {} from eBPF routing table", 
                          threadId, connectionId);
            } catch (Exception e) {
                logger.error("Selector-{}: Failed to remove CID: {} from eBPF map", 
                           threadId, connectionId, e);
            }

        } catch (Exception e) {
            logger.error("Selector-{}: Error evicting connection CID: {}", 
                       threadId, connectionId, e);
        }
    }

    @Override
    public boolean equals(Object obj) {
        return super.equals(obj);
    }

    /**
     * Skips over a single QUIC packet in the datagram buffer without processing it.
     * For long-header packets, reads the header fields to find the payload length varint,
     * then advances the buffer past the full packet (header + payload).
     * For short-header (1-RTT) packets, the entire remaining datagram is consumed
     * since there is no length field in a short header.
     *
     * @param datagram The datagram buffer positioned at the lower of the packet to skip
     */
     public static void skipPacket(ByteBuffer datagram) {
        try {
            byte flags = datagram.get();
            boolean isLongHeader = (flags & 0x80) != 0;

            if (!isLongHeader) {
                // Short header has no length field - consume the rest of the datagram
                datagram.position(datagram.limit());
                return;
            }

            // Long header: version (4) + DCID length (1) + DCID + SCID length (1) + SCID
            datagram.getInt(); // version
            int dcidLen = datagram.get() & 0xFF;
            datagram.position(datagram.position() + dcidLen);
            int scidLen = datagram.get() & 0xFF;
            datagram.position(datagram.position() + scidLen);

            // For INITIAL packets there is also a token; for RETRY/ZERO_RTT there is none,
            // but we check the type just in case.
            int typeField = (flags & 0x30) >> 4;
            if (typeField == 0x00) { // INITIAL - has a token length varint
                long tokenLen = QuicVarint.read(datagram);
                datagram.position((int) (datagram.position() + tokenLen));
            }

            // Payload length (varint) - includes the packet-number bytes and ciphertext
            long payloadLength = QuicVarint.read(datagram);
            datagram.position((int) (datagram.position() + payloadLength));

        } catch (Exception e) {
            logger.warn("Failed to skip unhandled packet, consuming rest of datagram", e);
            datagram.position(datagram.limit());
        }
    }

}

