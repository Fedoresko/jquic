package org.jquic.quic;

import ch.qos.logback.core.pattern.color.ANSIConstants;
import org.jquic.LogTool;
import org.jquic.quic.buffers.BufferPool;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.streamapi.impl.OutboxRecord;
import org.jctools.queues.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.LockSupport;

// =========================================================================
// SELECTOR THREAD LOGIC
// =========================================================================
public class SelectorThread implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(SelectorThread.class);
    private static final LogTool log = new LogTool(logger);
    public static final int OUTBOUND_APP_QUEUE_SIZE = 1000;
    public static final int HANDSHAKE_QUEUE_CAP = 1000;

    private final int threadId;
    private QuicDatagramChannel channel;
    private final DatagramChannel socket;
    private final SpscLinkedQueue<PacketData> forwardedPackets;
    private final SpscArrayQueue<HandshakeTask> handshakeQueue = new SpscArrayQueue<>(HANDSHAKE_QUEUE_CAP);
    private final MessagePassingQueue<OutboxRecord> applicationQueue = new MpscArrayQueue<>(OUTBOUND_APP_QUEUE_SIZE);
    private final ConcurrentHashMap<Long, Integer> cidToSelectorMap;
    private final Map<Long, QuicConnection> activeConnections;
    private final Map<ByteBuffer, QuicConnection> initializingConnections = new HashMap<>();
    private final MpscLinkedQueue<OutboxRecord> outputQueue = new MpscLinkedQueue<>();

    private final LinkedList<OutboxRecord>[] timerWheel = new LinkedList[2000];
    private long lastDrainedSlot = 0;

    private final BufferPool bufferPool = new BufferPool();

    // Timeout management: PriorityQueue ordered by timeout timestamp
    private final TimeoutHeap<QuicConnection> timeoutHeap = new TimeoutHeap<>(QuicConnection.class);
    private long lastTimeoutCheck = System.currentTimeMillis();
    private static final long TIMEOUT_CHECK_INTERVAL_MS = 1000; // Check every second
    private int idleCounter = 0;

    public BufferPool getBufferPool() {
        return bufferPool;
    }

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

    public SelectorThread(int threadId, DatagramChannel socket, ConcurrentHashMap<Long, Integer> cidToSelectorMap) throws IOException, NoSuchFieldException, IllegalAccessException {
        this.threadId = threadId;
        this.socket = socket;
        this.forwardedPackets = new SpscLinkedQueue<>();
        this.cidToSelectorMap = cidToSelectorMap;
        this.activeConnections = new HashMap<>();
        for (int i = 0; i < timerWheel.length; i++) {
            timerWheel[i] = new LinkedList<>();
        }
    }

    private static final String[] COLORS = new String[] { ANSIConstants.GREEN_FG, ANSIConstants.MAGENTA_FG, ANSIConstants.BLUE_FG, ANSIConstants.CYAN_FG};
    private String logColor() {
        return COLORS[threadId % COLORS.length];
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
            log.error(logColor(), "Selector-{}: Error enqueueing forwarded packet", threadId, e);
        }
    }

    public void forwardHandshake(HandshakeTask task) {
        handshakeQueue.offer(task);
    }

    @Override
    public void run() {
        try {
            this.channel = new QuicDatagramChannel(socket);

            // Configure channel for non-blocking to allow polling forwarded queue
            PoolBuffer buffer = getBufferPool().requestReadBuffer();

            int[] metricsHolder = new int[1];

            lastDrainedSlot = System.nanoTime() /10_000;

            while (!Thread.currentThread().isInterrupted()) {
                long nowNs = System.nanoTime();
                long now = nowNs / 1_000_000;

                boolean hadWork = false;

                // Process packets from socket
                SocketAddress sender = (idleCounter > 100) ?
                        channel.receiveBlocking(buffer.buf(), metricsHolder) :
                        channel.receive(buffer.buf(), metricsHolder);

                if (sender != null) {
                    buffer.buf().flip();
                    processPacket(now, buffer, sender, "socket", metricsHolder[0]);
                    hadWork = true;
                    buffer = getBufferPool().requestReadBuffer();
                }

                // Process forwarded packets
                PacketData forwarded = forwardedPackets.poll();
                if (forwarded != null) {
                    processPacket(now, forwarded.buffer, forwarded.sender, "forwarded", 0);
                    hadWork = true;
                }

                HandshakeTask handshakeTask = handshakeQueue.poll();
                if (handshakeTask != null) {
                    processHandshakeTask(now, handshakeTask);
                    hadWork = true;
                }

                long curSlot = (nowNs / 10_000);
                // Drain application queue and process packages for all active connections.
                applicationQueue.drain(rec-> {
                    long slot = (rec.timeToSendNs() / 10_000);
                    if (lastDrainedSlot > slot) lastDrainedSlot = slot;
                    if (slot - curSlot > timerWheel.length - 2) { slot = curSlot + timerWheel.length - 2; }
                    timerWheel[(int)(slot % timerWheel.length)].add(rec);
                });

                if (curSlot - lastDrainedSlot > timerWheel.length - 1) {
                    lastDrainedSlot = curSlot - timerWheel.length + 1;
                }

                OutboxRecord appPacket;
                for (long slot = lastDrainedSlot; slot <= curSlot; slot ++) {
                    while ((appPacket = timerWheel[(int)(slot % timerWheel.length)].poll()) != null) {
                        hadWork |= processApplicationPacket(appPacket, now);
                    }
                }
                lastDrainedSlot = curSlot;

                // Check for timed out connections periodically
                if (now - lastTimeoutCheck > TIMEOUT_CHECK_INTERVAL_MS) {
                    evictTimedOutConnections(now);
                    lastTimeoutCheck = now;
                }

                if (!hadWork) {
                    LockSupport.parkNanos(1000);
                    idleCounter++;
                } else {
                    idleCounter = 0;
                }
            }
        } catch (Exception e) {
            log.error(logColor(), "Selector-{}: Error in selector thread", threadId, e);
        }
    }

    private boolean processApplicationPacket(OutboxRecord appPacket, long now) throws IOException {
        QuicConnection conn = activeConnections.get(appPacket.connectionId());
        if (conn != null) {
            logger.debug("Polled application data frame cid {}", conn.getConnectionId());
            conn.setCurrentTimestamp(now);

            conn.send1RttPacket(appPacket.data());
            // Update timeout in heap after processing
            timeoutHeap.insertOrUpdate(conn);

            PoolBuffer outbound;
            if (conn.outboundQueueSize() > 0) {
                log.debug(logColor(), "Selector-{}: Connection CID: {} sending {} response packets.", threadId, conn.getConnectionId(), conn.outboundQueueSize());
            }

            while ((outbound = conn.pollOutbound()) != null) {
                channel.send(outbound.buf(), conn.getRemoteAddress());
                outbound.release();
            }

            return true;
        }
        return false;
    }
//
//    static class StatsFile implements AutoCloseable {
//        private final RandomAccessFile file;
//        private final FileChannel channel;
//        private final String name;
//        StatsFile(String name, String path) throws FileNotFoundException {
//            file = new RandomAccessFile(path, "rw");
//            this.name = name;
//            channel = file.getChannel();
//        }
//        public void put(String val) {
//            try {
//                log.info("Stats {} : {}", name, val);
//                byte[] bytes = val.getBytes(StandardCharsets.UTF_8);
//                MappedByteBuffer buffer = channel.map(FileChannel.MapMode.READ_WRITE, 0, bytes.length);
//                buffer.put(bytes);
//                buffer.force();
//            } catch (IOException e) {
//                logger.warn("Could not update stats file {}", name, e);
//            }
//        }
//
//        @Override
//        public void close() throws IOException {
//            channel.close();
//            file.close();
//        }
//    }


    /**
     * Processes a received datagram which may contain multiple coalesced packets.
     * Routes packets to appropriate connections based on CID.
     */
    private void processPacket(long now, PoolBuffer datagram, SocketAddress sender, String source, int ecnFlags) {
        try {
            int packetCount = 0;

            // Process all coalesced packets in the datagram
            while (datagram.buf().hasRemaining()) {
                if (datagram.buf().remaining() < 9) { // Minimum: 1 byte flags + 8 bytes CID
                    log.debug(logColor(), "Selector-{}: Remaining bytes too short for packet: {}", 
                               threadId, datagram.buf().remaining());
                    break;
                }

                QuicPacketHeader.PacketSummary packetSummary = QuicPacketHeader.parseSummary(datagram.buf());

                if (packetSummary == null || packetSummary.type() == QuicPacketHeader.PacketType.RETRY) {
                    break; //invalid data skip remaining
                }

                packetCount++;
                log.debug(logColor(), "Selector-{}: Packet {} in datagram from {} for CID: {}, type: {}",
                           threadId, packetCount, source, packetSummary.dcid(), packetSummary.type());

                ByteBuffer dcid = ByteBuffer.wrap(packetSummary.dcid());
                long cid = dcid.duplicate().getLong();

                // Look up connection
                QuicConnection connection = activeConnections.get(cid);
                if (connection == null) {
                    connection = initializingConnections.get(dcid);
                }

                if (packetSummary.type() == QuicPacketHeader.PacketType.ZERO_RTT ) {
                    log.warn(logColor(), "Selector-{}: Processing {} packet for CID: {} not implemented",threadId, packetSummary.type(), cid);
                    skipPacket(datagram.buf());
                    continue;
                }

                if (connection == null) {
                    log.warn(logColor(), "Selector-{}: No connection found for CID: {}, discarding datagram", threadId, cid);
                    evictConnection(cid);
                    break;
                }

                if (!connection.getRemoteAddress().equals(sender)) {
                    log.warn(logColor(), "Selector-{} CID: {}, different remote address, discarding datagram", threadId, cid);
                    break;
                }

                // Route packet to connection for processing
                // Buffer position advances automatically as packet is read
                try {
                    connection.setCurrentTimestamp(now);

                    switch (packetSummary.type()) {
                        case INITIAL -> {
                            log.debug(logColor(), "Selector-{}: Processing Initial packet for CID: {}", threadId, cid);
                            connection.processInitialAndRespond(datagram);
                        }
                        case HANDSHAKE ->  { // Handshake packet (0b10)
                            log.debug(logColor(), "Selector-{}: Processing Handshake packet for CID: {}", threadId, cid);
                            connection.processHandshakePacket(datagram);
                        }
                        case ONE_RTT -> {
                            log.debug(logColor(), "Selector-{}: Processing 1-RTT packet for CID: {} from: {}", threadId, cid, sender);
                            connection.process1RttPacket(datagram, ecnFlags);
                        }
                        case RETRY, ZERO_RTT -> {
                            log.warn(logColor(), "Selector-{}: Processing {} packet for CID: {} not implemented",threadId, packetSummary.type(), cid);
                            skipPacket(datagram.buf());
                        }
                    }
                    // Update timeout in heap after processing (remove-add pattern)
                    timeoutHeap.insertOrUpdate(connection);

                    // Drain any packets the connection produced internally (e.g. early-1RTT
                    // replay triggered by the ESTABLISHED transition, or sendFrame() calls).
                    PoolBuffer outbound;
                    log.info(logColor(), "Selector-{}: Connection CID: {} sending {} response packets.", threadId, cid, connection.outboundQueueSize());
                    while ((outbound = connection.pollOutbound()) != null) {
                        channel.send(outbound.buf(), connection.getRemoteAddress());
                        outbound.release();
                    }
                } catch (Exception e) {
                    log.error(logColor(), "Selector-{}: Failed to process packet for CID: {}", threadId, cid, e);
                    break;
                }
            }

            log.debug(logColor(), "Selector-{}: Processed {} packet(s) from datagram", threadId, packetCount);
        } catch (Exception e) {
            log.error(logColor(), "Selector-{}: Error processing datagram from {}", threadId, source, e);
        } finally {
            datagram.release();
        }
    }

    /**
     * Processes Initial packet from new connection.
     * Creates connection and sends Initial response (ServerHello).
     * Handshake will continue when client sends Handshake packet.
     */
    private void processHandshakeTask(long now, HandshakeTask task) {
        try {
            log.warn(logColor(), "Selector-{}: Processing Initial packet for new CID: {}", threadId, task.allocatedCid);

            QuicConnection connection = activeConnections.computeIfAbsent(task.allocatedCid,
                    cid -> new QuicConnection(task.allocatedCid, task.sender, applicationQueue,this));
            connection.setCurrentTimestamp(now);

            assignConnectionToSelector(connection.getConnectionId());

            ByteBuffer dcidKey = ByteBuffer.wrap(task.packetSummary.dcid());
            initializingConnections.put(dcidKey, connection);

            processPacket(now, task.packet, task.sender, "initial", 0);

            initializingConnections.remove(dcidKey);

            // Register this selector as the owner of the connection
            log.info(logColor(), "Selector-{}: Initial processed for CID: {}, first datagram processing finished",
                      threadId, task.allocatedCid);
        } catch (Exception e) {
            log.error(logColor(), "Selector-{}: Initial packet processing error for CID: {}", threadId, task.allocatedCid, e);
        }
    }

    private void assignConnectionToSelector(long connectionId) {
        log.info(logColor(), "Connection {} assigned to Selector {}", connectionId, threadId);

        // Update eBPF map if available
        try {
            BpfRouting.updateRouting(connectionId, threadId+1);
        } catch (Exception e) {
            log.error(logColor(), "Failed to update eBPF map for connection {}", connectionId, e);
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

            log.warn(logColor(), "Selector-{}: Connection CID: {} timed out at {}, evicting (now is: {})",
                       threadId, connection.getConnectionId(), connection.getTimeoutTimestamp(), now);
            evictConnection(connection.getConnectionId());
            evictedCount++;
        }

        if (evictedCount > 0) {
            log.info(logColor(), "Selector-{}: Evicted {} timed out connection(s)", threadId, evictedCount);
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
                log.info(logColor(), "Selector-{}: Evicted connection CID: {} from activeConnections", 
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
                log.info(logColor(), "Selector-{}: Removed CID: {} from eBPF routing table", 
                          threadId, connectionId);
            } catch (Exception e) {
                log.error(logColor(), "Selector-{}: Failed to remove CID: {} from eBPF map", 
                           threadId, connectionId, e);
            }

        } catch (Exception e) {
            log.error(logColor(), "Selector-{}: Error evicting connection CID: {}", 
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
                // Short header has no length field — consume the rest of the datagram
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
            if (typeField == 0x00) { // INITIAL — has a token length varint
                long tokenLen = QuicVarint.read(datagram);
                datagram.position((int) (datagram.position() + tokenLen));
            }

            // Payload length (varint) — includes the packet-number bytes and ciphertext
            long payloadLength = QuicVarint.read(datagram);
            datagram.position((int) (datagram.position() + payloadLength));

        } catch (Exception e) {
            logger.warn("Failed to skip unhandled packet, consuming rest of datagram", e);
            datagram.position(datagram.limit());
        }
    }

}
