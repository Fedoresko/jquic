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

import org.jquic.quic.buffers.BufferPool;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.crypto.QuicCrypto;
import org.jquic.quic.struct.LruCache;
import org.jquic.quic.struct.MurmurHash3;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import static org.jquic.quic.SelectorThread.skipPacket;

// =========================================================================
// ACCEPTOR THREAD LOGIC
// =========================================================================
class AcceptorThread implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(AcceptorThread.class);
    public static final int INITIAL_CONNECTIONS_MAP_SIZE = 1000;
    public static final int MINIMUM_INITIAL_PACKET = 1200;

    private final BufferPool bufferPool = new BufferPool();

    private final DatagramChannel channel;
    private SelectorThread[] selectors;
    private final ConcurrentHashMap<Long, Integer> cidToSelectorMap;
    private final AtomicLong cidGenerator;

    record SelectorCID(Integer selectorId, Long cid) {
    }

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
        long[] hash128 = MurmurHash3.hash(bytes);
        return hash128[0] & Long.MAX_VALUE;
    }

    @Override
    public void run() {
        try {
            while (!Thread.currentThread().isInterrupted()) {
                // Get a buffer from pool for this receive operation
                PoolBuffer buffer = bufferPool.requestReadBuffer();

                int start = buffer.buf().position();
                SocketAddress sender = channel.receive(buffer.buf());
                buffer.buf().limit(buffer.buf().position());
                buffer.buf().position(start);
                int datagramSize = buffer.buf().remaining();

                if (buffer.buf().remaining() > 0) {
                    QuicPacketHeader.PacketSummary packetSummary = QuicPacketHeader.parseSummary(buffer.buf());
                    if (packetSummary == null) {
                        logger.info("Could not parse paket summary");
                        continue; // skip remaining
                    }

                    if (packetSummary.type() != QuicPacketHeader.PacketType.ONE_RTT &&
                        packetSummary.type() != QuicPacketHeader.PacketType.ZERO_RTT &&
                        packetSummary.version() == QuicVersion.UNKNOWN) {
                        logger.info("[Acceptor] Unsupported QUIC version. Sending Version Negotiation.");
                        // Send Version Negotiation: DCID = received SCID, SCID = received DCID

                        if (datagramSize >= 1200) { // Minimum packet size requirement
                            PoolBuffer vnPacket = QuicPacketBuilder.buildVersionNegotiationPacket(bufferPool, packetSummary.scid(), packetSummary.dcid());
                            try {
                                channel.send(vnPacket.buf(), sender);
                            } catch (Exception e) {
                                logger.error("Failed to send Version Negotiation packet", e);
                            }
                            vnPacket.release();
                        }
                        continue;
                    }

                    byte[] dcid = packetSummary.dcid();
                    logger.debug("[Acceptor] Received {} packet, DCID: {}, SCID {}", packetSummary.type(), HexFormat.of().formatHex(dcid), packetSummary.scid() == null ? "null" : HexFormat.of().formatHex(packetSummary.scid()));

                    SelectorCID assignedSelectorId = initialSelectorMap.get(ByteBuffer.wrap(dcid));
                    if (assignedSelectorId != null) {
                        logger.debug("[Acceptor] Packet in initialization mapping  CID: {}, enqueueing for handshake", assignedSelectorId.cid);

                        buffer.buf().rewind();
                        selectors[assignedSelectorId.selectorId].forwardHandshake(
                                new HandshakeTask(buffer.borrow(), sender, assignedSelectorId.cid(), packetSummary)
                        );
                    } else {
                        long cid = ByteBuffer.wrap(dcid).getLong();
                        // Look up the Selector assignment from our stored mapping
                        Integer owningSelectorId = cidToSelectorMap.get(cid);

                        if (owningSelectorId != null) {
                            logger.debug("[Acceptor] Packet in regular mapping  CID: {}, forwarding to selector", owningSelectorId);
                            // Forward this packet to the appropriate Selector
                            forwardToSelector(owningSelectorId, buffer, sender);
                        } else {
                            if (packetSummary.type() == QuicPacketHeader.PacketType.INITIAL
                                    && buffer.buf().remaining() >= MINIMUM_INITIAL_PACKET) {
                                // LONG HEADER: Generate CID and enqueue for handshake processing
                                long newCid = cidGenerator.getAndIncrement();
                                logger.warn("[Acceptor] First initial packet, allocated CID: {}, enqueueing for handshake", newCid);

                                int selectorId = (int) (getLongHash(dcid) % selectors.length);

                                initialSelectorMap.put(ByteBuffer.wrap(dcid), new SelectorCID(selectorId, newCid));
                                cidToSelectorMap.put(newCid, selectorId);

                                buffer.buf().rewind();
                                selectors[selectorId].forwardHandshake(
                                        new HandshakeTask(buffer.borrow(), sender, newCid, packetSummary)
                                );
                            } else if (packetSummary.type() == QuicPacketHeader.PacketType.ZERO_RTT) {
                                long newCid = cidGenerator.getAndIncrement();
                                logger.warn("[Acceptor] First zero-rtt packet, allocated CID: {}, enqueueing for handshake", newCid);

                                int selectorId = (int) (getLongHash(dcid) % selectors.length);
                                initialSelectorMap.put(ByteBuffer.wrap(dcid), new SelectorCID(selectorId, newCid));
                                cidToSelectorMap.put(newCid, selectorId);
                                buffer.buf().rewind();
                                selectors[selectorId].forwardHandshake(
                                        new HandshakeTask(buffer.borrow(), sender, newCid, packetSummary)
                                );

                            } else if (packetSummary.type() != QuicPacketHeader.PacketType.INITIAL) {
                                skipPacket(buffer.buf());

                                logger.warn("[Acceptor] Non-Initial packed with unknown DCID: {} type {} - no mapping found, sending STATELESS_RESET", dcid, packetSummary.type());
                                int incomingPacketSize = buffer.buf().position() - start;
                                if (incomingPacketSize > 25) { //ignore to small packets
                                    byte[] statelessResetToken = QuicCrypto.generateStatelessResetToken(dcid);
                                    PoolBuffer resetPacket = QuicPacketBuilder.writeStatelessResetFrame(bufferPool, incomingPacketSize, statelessResetToken);
                                    try {
                                        channel.send(resetPacket.buf(), sender);
                                    } catch (Exception e) {
                                        logger.error("Failed to send Stateless Reset packet", e);
                                    }
                                    resetPacket.release();
                                }
                            } else {
                                buffer.buf().position(buffer.buf().limit());
                                logger.warn("[Acceptor] Initial packed with unknown DCID: {} too short {}  dropping packet", dcid, buffer.buf().remaining());
                            }
                        }
                    }
                }

                buffer.release();
            }
        } catch (Exception e) {
            logger.error("Error in acceptor thread", e);
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

