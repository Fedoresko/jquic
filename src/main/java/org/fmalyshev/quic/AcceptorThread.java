package org.fmalyshev.quic;

import ch.qos.logback.core.pattern.color.ANSIConstants;
import org.apache.commons.codec.digest.MurmurHash3;
import org.fmalyshev.LogTool;
import org.fmalyshev.quic.buffers.PoolBuffer;
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
    public static final int INITIAL_CONNECTIONS_MAP_SIZE = 1000;
    public static final int MINIMUM_INITIAL_PACKET = 1200;

    private final DatagramChannel channel;
    private SelectorThread[] selectors;
    private final ConcurrentHashMap<Long, Integer> cidToSelectorMap;
    private final AtomicLong cidGenerator;

    record SelectorCID (Integer selectorId, Long cid) {}
    private final LruCache<ByteBuffer, SelectorCID> initialSelectorMap = new LruCache<>(INITIAL_CONNECTIONS_MAP_SIZE);

    public AcceptorThread(DatagramChannel channel, ConcurrentHashMap<Long, Integer> cidToSelectorMap) {
        this.channel = channel;
        this.selectors = null; // Will be set after selectors are initialized
        this.cidToSelectorMap = cidToSelectorMap;
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
                PoolBuffer buffer = QuicEngine.getPool().requestReadBuffer();

                SocketAddress sender = channel.receive(buffer.buf());
                buffer.buf().flip();

                if (buffer.buf().remaining() > 0) {
                    QuicPacketHeader.PacketSummary packetSummary = QuicPacketHeader.parseSummary(buffer.buf());
                    if (packetSummary == null) {
                        log.warn(ANSIConstants.RED_FG, "Could not parse paket summary");
                        break; // skip remaining
                    }
                    byte[] dcid = packetSummary.dcid();
                    log.debug(ANSIConstants.RED_FG, "[Acceptor] Received {} packet, DCID: {}", packetSummary.type(), dcid);

                    SelectorCID assignedSelectorId = initialSelectorMap.get(ByteBuffer.wrap(dcid));
                    if (assignedSelectorId != null) {
                        log.warn(ANSIConstants.RED_FG, "[Acceptor] Packet in initialization mapping  CID: {}, enqueueing for handshake", assignedSelectorId.cid);

                        buffer.buf().rewind();
                        selectors[assignedSelectorId.selectorId].forwardHandshake(
                                new HandshakeTask(buffer.borrow(), sender, assignedSelectorId.cid())
                        );
                    } else {
                        long cid = ByteBuffer.wrap(dcid).getLong();
                        // Look up the Selector assignment from our stored mapping
                        Integer owningSelectorId = cidToSelectorMap.get(cid);

                        if (owningSelectorId != null) {
                            log.debug(ANSIConstants.RED_FG, "[Acceptor] Packet in regular mapping  CID: {}, forwarding to selector", owningSelectorId);
                            // Forward this packet to the appropriate Selector
                            forwardToSelector(owningSelectorId, buffer, sender);
                        } else {
                            if (packetSummary.type() == QuicPacketHeader.PacketType.INITIAL && buffer.buf().remaining() >= MINIMUM_INITIAL_PACKET) {
                                // LONG HEADER: Generate CID and enqueue for handshake processing
                                long newCid = cidGenerator.getAndIncrement();
                                log.warn(ANSIConstants.RED_FG, "[Acceptor] First initial packet, allocated CID: {}, enqueueing for handshake", newCid);

                                int selectorId = (int) (getLongHash(dcid) % selectors.length);

                                initialSelectorMap.put(ByteBuffer.wrap(dcid), new SelectorCID(selectorId, newCid));

                                buffer.buf().rewind();
                                selectors[selectorId].forwardHandshake(
                                        new HandshakeTask(buffer.borrow(), sender, newCid)
                                );
                            } else if (packetSummary.type() != QuicPacketHeader.PacketType.INITIAL) {
                                skipPacket(buffer.buf());
                                log.warn(ANSIConstants.RED_FG, "[Acceptor] Non-Initial packed with unknown DCID: {} type {} - no mapping found, dropping packet", dcid, packetSummary.type());
                            } else {
                                buffer.buf().position(buffer.buf().limit());
                                log.warn(ANSIConstants.RED_FG, "[Acceptor] Initial packed with unknown DCID: {} too short {}  dropping packet", dcid, buffer.buf().remaining());
                            }
                        }
                    }
                }

                buffer.release();
            }
        } catch (Exception e) {
            log.error(ANSIConstants.RED_FG, "Error in acceptor thread", e);
        }
    }

    private void forwardToSelector(Integer assignedSelectorId, PoolBuffer buffer, SocketAddress sender) {
        if (selectors != null && assignedSelectorId < selectors.length) {
            SelectorThread targetSelector = selectors[assignedSelectorId];
            if (targetSelector != null) {
                // Transfer ownership of buffer to selector thread
                buffer.buf().rewind();
                targetSelector.forwardPacket(buffer.borrow(), sender);
            }
        }
    }

}
