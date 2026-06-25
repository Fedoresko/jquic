package org.fmalyshev.quic;

import ch.qos.logback.core.pattern.color.ANSIConstants;
import org.apache.commons.codec.digest.MurmurHash3;
import org.fmalyshev.LogTool;
import org.jctools.queues.MpscArrayQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import static org.fmalyshev.quic.SelectorThread.skipPacket;

// =========================================================================
// ACCEPTOR THREAD LOGIC
// =========================================================================
class AcceptorThread implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(AcceptorThread.class);
    private static final LogTool log = new LogTool(logger);
    private static final int BUFFER_SIZE = 2048;
    public static final int INITIAL_CONNECTIONS_MAP_SIZE = 1000;

    private final DatagramChannel channel;
    private SelectorThread[] selectors;
    private final ConcurrentHashMap<Long, Integer> cidToSelectorMap;
    private final MpscArrayQueue<ByteBuffer> bufferPool;
    private final AtomicLong cidGenerator;

    record SelectorCID (Integer selectorId, Long cid) {}
    private final LruCache<ByteBuffer, SelectorCID> initialSelectorMap = new LruCache<>(INITIAL_CONNECTIONS_MAP_SIZE);

    public AcceptorThread(DatagramChannel channel, MpscArrayQueue<ByteBuffer> bufferPool,
                         ConcurrentHashMap<Long, Integer> cidToSelectorMap) {
        this.channel = channel;
        this.selectors = null; // Will be set after selectors are initialized
        this.cidToSelectorMap = cidToSelectorMap;
        this.bufferPool = bufferPool;
        this.cidGenerator = new AtomicLong(1); // Start from 1
    }

    public void setSelectors(SelectorThread[] selectors) {
        this.selectors = selectors;
    }

    private static long getLongHash(byte[] bytes) {
        long[] hash128 = MurmurHash3.hash128x64(bytes);
        return hash128[0] & Long.MAX_VALUE;
    }

    @Override
    public void run() {
        try {
            while (!Thread.currentThread().isInterrupted()) {
                // Get a buffer from pool for this receive operation
                ByteBuffer buffer = bufferPool.poll();
                if (buffer == null) {
                    buffer = ByteBuffer.allocate(BUFFER_SIZE);
                }

                buffer.clear();
                SocketAddress sender = channel.receive(buffer);
                buffer.flip();

                boolean bufferTransferred = false;

                if (buffer.remaining() > 0) {
                    QuicPacketHeader.PacketSummary packetSummary = QuicPacketHeader.parseSummary(buffer);
                    if (packetSummary == null) {
                        log.warn(ANSIConstants.RED_FG, "Could not parse paket summary");
                        break; // skip remaining
                    }
                    byte[] dcid = packetSummary.dcid();
                    log.debug(ANSIConstants.RED_FG, "[Acceptor] Received {} packet, DCID: {}", packetSummary.type(), dcid);

                    SelectorCID assignedSelectorId = initialSelectorMap.get(ByteBuffer.wrap(dcid));
                    if (assignedSelectorId != null) {
                        log.debug(ANSIConstants.RED_FG, "[Acceptor] Packet in initialization mapping  CID: {}, enqueueing for handshake", assignedSelectorId.cid);

                        buffer.rewind();
                        selectors[assignedSelectorId.selectorId].forwardHandshake(
                                new HandshakeTask(buffer, sender, assignedSelectorId.cid())
                        );
                        bufferTransferred = true;
                    } else {
                        long cid = ByteBuffer.wrap(dcid).getLong();
                        // Look up the Selector assignment from our stored mapping
                        Integer owningSelectorId = cidToSelectorMap.get(cid);

                        if (owningSelectorId != null) {
                            log.debug(ANSIConstants.RED_FG, "[Acceptor] Packet in regular mapping  CID: {}, forwarding to selector", owningSelectorId);
                            // Forward this packet to the appropriate Selector
                            bufferTransferred = forwardToSelector(owningSelectorId, buffer, sender);
                        } else {
                            if (packetSummary.type() == QuicPacketHeader.PacketType.INITIAL) {
                                // LONG HEADER: Generate CID and enqueue for handshake processing
                                long newCid = cidGenerator.getAndIncrement();
                                log.debug(ANSIConstants.RED_FG, "[Acceptor] First initial packet, allocated CID: {}, enqueueing for handshake", newCid);

                                int selectorId = (int) (getLongHash(dcid) % selectors.length);

                                initialSelectorMap.put(ByteBuffer.wrap(dcid), new SelectorCID(selectorId, newCid));

                                buffer.rewind();
                                selectors[selectorId].forwardHandshake(
                                        new HandshakeTask(buffer, sender, newCid)
                                );

                                bufferTransferred = true;
                            } else {
                                skipPacket(buffer);
                                log.warn(ANSIConstants.RED_FG, "[Acceptor] Non-Initial packed with unknown DCID: {} type {} - no mapping found, dropping packet", dcid, packetSummary.type());
                            }
                        }
                    }
                }

                // Return buffer to pool if ownership was not transferred
                if (!bufferTransferred) {
                    bufferPool.offer(buffer);
                }
            }
        } catch (Exception e) {
            log.error(ANSIConstants.RED_FG, "Error in acceptor thread", e);
        }
    }

    private boolean forwardToSelector(Integer assignedSelectorId, ByteBuffer buffer, SocketAddress sender) {
        if (selectors != null && assignedSelectorId < selectors.length) {
            SelectorThread targetSelector = selectors[assignedSelectorId];
            if (targetSelector != null) {
                // Transfer ownership of buffer to selector thread
                buffer.rewind();
                targetSelector.forwardPacket(buffer, sender);
                return true;
            }
        }
        return false;
    }

}
