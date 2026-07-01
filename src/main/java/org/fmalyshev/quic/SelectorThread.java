package org.fmalyshev.quic;

import ch.qos.logback.core.pattern.color.ANSIConstants;
import org.fmalyshev.LogTool;
import org.jctools.queues.MpscArrayQueue;
import org.jctools.queues.SpscArrayQueue;
import org.jctools.queues.SpscLinkedQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// =========================================================================
// SELECTOR THREAD LOGIC
// =========================================================================
class SelectorThread implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(SelectorThread.class);
    private static final LogTool log = new LogTool(logger);

    public static final int HANDSHAKE_QUEUE_CAP = 1000;
    private final int threadId;
    private final DatagramChannel channel;
    private final SpscLinkedQueue<PacketData> forwardedPackets;
    private final MpscArrayQueue<ByteBuffer> bufferReturnPool;
    private final SpscArrayQueue<HandshakeTask> handshakeQueue = new SpscArrayQueue<>(HANDSHAKE_QUEUE_CAP);
    private final ConcurrentHashMap<Long, Integer> cidToSelectorMap;
    private final Map<Long, QuicConnection> activeConnections;
    private final Map<ByteBuffer, QuicConnection> initializingConnections = new HashMap<>();

    // Timeout management: PriorityQueue ordered by timeout timestamp
    private final TimeoutHeap<QuicConnection> timeoutHeap = new TimeoutHeap<>(QuicConnection.class);
    private long lastTimeoutCheck = System.currentTimeMillis();
    private static final long TIMEOUT_CHECK_INTERVAL_MS = 1000; // Check every second

    public class WriteBuffer {
        private final ByteBuffer buffer = ByteBuffer.allocateDirect(65535);
        private  SocketAddress sender;



        public void send() throws IOException {
            channel.send(buffer, sender);
            buffer.clear();
        }
    }

    /**
     * Encapsulates a packet with its sender address for forwarding between threads.
     */
    private static class PacketData {
        final ByteBuffer buffer;
        final SocketAddress sender;

        PacketData(ByteBuffer buffer, SocketAddress sender) {
            this.buffer = buffer;
            this.sender = sender;
        }
    }

    public SelectorThread(int threadId, DatagramChannel channel, MpscArrayQueue<ByteBuffer> bufferReturnPool,
                         ConcurrentHashMap<Long, Integer> cidToSelectorMap) {
        this.threadId = threadId;
        this.channel = channel;
        this.forwardedPackets = new SpscLinkedQueue<>();
        this.bufferReturnPool = bufferReturnPool;
        this.cidToSelectorMap = cidToSelectorMap;
        this.activeConnections = new HashMap<>();
    }

    private static String[] COLORS = new String[] { ANSIConstants.GREEN_FG, ANSIConstants.MAGENTA_FG, ANSIConstants.BLUE_FG, ANSIConstants.CYAN_FG};
    private String logColor() {
        return COLORS[threadId % COLORS.length];
    }

    /**
     * Forwards a packet received by AcceptorThread to this Selector.
     * This is used when a short header packet arrives with an unknown CID.
     * Zero-copy implementation: takes ownership of the ByteBuffer.
     * The buffer will be returned to the pool after processing.
     */
    public void forwardPacket(ByteBuffer packet, SocketAddress sender) {
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
        ByteBuffer buffer = ByteBuffer.allocateDirect(2048);
        try {
            // Configure channel for non-blocking to allow polling forwarded queue
            channel.configureBlocking(false);

            while (!Thread.currentThread().isInterrupted()) {
                long now = System.currentTimeMillis();

                boolean hadWork = false;

                // Process packets from socket
                buffer.clear();
                SocketAddress sender = channel.receive(buffer);
                if (sender != null) {
                    buffer.flip();
                    processPacket(buffer, sender, "socket");
                    hadWork = true;
                }

                // Process forwarded packets
                PacketData forwarded = forwardedPackets.poll();
                if (forwarded != null) {
                    processPacket(forwarded.buffer, forwarded.sender, "forwarded");
                    bufferReturnPool.offer(forwarded.buffer);
                    hadWork = true;
                }

                HandshakeTask handshakeTask = handshakeQueue.poll();
                if (handshakeTask != null) {
                    processHandshakeTask(handshakeTask);
                    bufferReturnPool.offer(handshakeTask.packet);
                    hadWork = true;
                }

                // Check for timed out connections periodically
                if (now - lastTimeoutCheck > TIMEOUT_CHECK_INTERVAL_MS) {
                    evictTimedOutConnections();
                    lastTimeoutCheck = now;
                }

                if (!hadWork) {
                    Thread.sleep(1);
                }
            }
        } catch (Exception e) {
            log.error(logColor(), "Selector-{}: Error in selector thread", threadId, e);
        }
    }

    /**
     * Processes a received datagram which may contain multiple coalesced packets.
     * Routes packets to appropriate connections based on CID.
     */
    private void processPacket(ByteBuffer datagram, SocketAddress sender, String source) {
        try {
            int packetCount = 0;

            // Process all coalesced packets in the datagram
            while (datagram.hasRemaining()) {
                if (datagram.remaining() < 9) { // Minimum: 1 byte flags + 8 bytes CID
                    log.debug(logColor(), "Selector-{}: Remaining bytes too short for packet: {}", 
                               threadId, datagram.remaining());
                    break;
                }

                QuicPacketHeader.PacketSummary packetSummary = QuicPacketHeader.parseSummary(datagram);

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
                    skipPacket(datagram);
                    continue;
                }

                if (connection == null) {
                    log.warn(logColor(), "Selector-{}: No connection found for CID: {}, discarding datagram", threadId, cid);
                    break;
                }

                if (!connection.getRemoteAddress().equals(sender)) {
                    log.warn(logColor(), "Selector-{} CID: {}, different remote address, discarding datagram", threadId, cid);
                    break;
                }

                // Route packet to connection for processing
                // Buffer position advances automatically as packet is read
                try {
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
                            connection.process1RttPacket(datagram);
                        }
                        case RETRY, ZERO_RTT -> {
                            log.warn(logColor(), "Selector-{}: Processing {} packet for CID: {} not implemented",threadId, packetSummary.type(), cid);
                            skipPacket(datagram);
                        }
                    };

                    // Update timeout in heap after processing (remove-add pattern)
                    timeoutHeap.insertOrUpdate(connection);

                    // Drain any packets the connection produced internally (e.g. early-1RTT
                    // replay triggered by the ESTABLISHED transition, or sendFrame() calls).
                    ByteBuffer outbound;
                    log.info(logColor(), "Selector-{}: Connection CID: {} sending {} response packets.", threadId, cid, connection.outboundQueueSize());
                    while ((outbound = connection.pollOutbound()) != null) {
                        channel.send(outbound, connection.getRemoteAddress());
                    }
                } catch (Exception e) {
                    log.error(logColor(), "Selector-{}: Failed to process packet for CID: {}", threadId, cid, e);
                    break;
                }
            }

            log.debug(logColor(), "Selector-{}: Processed {} packet(s) from datagram", threadId, packetCount);

        } catch (Exception e) {
            log.error(logColor(), "Selector-{}: Error processing datagram from {}", threadId, source, e);
        }
    }

    /**
     * Processes Initial packet from new connection.
     * Creates connection and sends Initial response (ServerHello).
     * Handshake will continue when client sends Handshake packet.
     */
    private void processHandshakeTask(HandshakeTask task) {
        try {
            log.debug(logColor(), "Selector-{}: Processing Initial packet for new CID: {}", threadId, task.allocatedCid);

            QuicPacketHeader.PacketSummary packetSummary = QuicPacketHeader.parseSummary(task.packet);
            if (packetSummary == null) {
                return;
            }

            QuicConnection connection = activeConnections.computeIfAbsent(task.allocatedCid,
                    cid -> new QuicConnection(task.allocatedCid, task.sender));

            assignConnectionToSelector(connection.getConnectionId());

            ByteBuffer dcidKey = ByteBuffer.wrap(packetSummary.dcid());
            initializingConnections.put(dcidKey, connection);

            processPacket(task.packet, task.sender, "initial");

            initializingConnections.remove(dcidKey);

            // Register this selector as the owner of the connection
            log.info(logColor(), "Selector-{}: Initial processed for CID: {}, first datagram processing finished",
                      threadId, task.allocatedCid);
        } catch (Exception e) {
            log.error(logColor(), "Selector-{}: Initial packet processing error for CID: {}", threadId, task.allocatedCid, e);
        }
    }

    private void assignConnectionToSelector(long connectionId) {
        cidToSelectorMap.put(connectionId, threadId);

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
    private void evictTimedOutConnections() {
        long now = System.currentTimeMillis();
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
     * @param datagram The datagram buffer positioned at the start of the packet to skip
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
