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
package org.jquic.quic.packets;

import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.paths.ConnectionPath;
import org.jquic.quic.paths.ConnectionPathController;
import org.jquic.quic.struct.SortedIntervals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.*;
import java.util.function.Function;

/**
 * Manages packet number space for a specific encryption level (Initial, Handshake, or Application).
 * Implements packet number allocation, ACK tracking, and loss detection per RFC 9000 and 9002.
 */
public class PacketNumberSpace {
    private static final Logger logger = LoggerFactory.getLogger(PacketNumberSpace.class);

    // RFC 9002: Loss detection constants
    private static final double K_TIME_THRESHOLD = 9.0 / 8.0; // 1.125
    private static final int MIN_K_PACKET_THRESHOLD = 3; // Packet reordering threshold
    public static final int MIN_LOSS_TIMEOUT = 200;

    public final PacketPhase phase; // For logging: "Initial", "Handshake", "Application"

    // Packet number allocation
    private long nextPacketNumber = 0;

    private int kPacketThreshold = MIN_K_PACKET_THRESHOLD;
    private int firstAckedRangeLen;
    private long lastLossDetectedMs = 0;

    // Received packet tracking
    private long largestReceivedPacketNumber = -1;
    private long largestReceivedPacketTimestamp = -1;
    private final SortedIntervals receivedPackets = new SortedIntervals(255);

    // Sent packet tracking - TreeMap keeps packet numbers sorted so the packet-threshold
    // pass in detectLostPackets can use headMap() instead of scanning the full table.
    private final TreeMap<Long, SentPacket> sentPackets = new TreeMap<>();
    private long largestAckedPacketNumber = -1;

    private ConnectionPathController connectionPathController;

    public long clientEctCeCounter = 0;
    public long clientEct0Counter = 0;
    public long clientEct1Counter = 0;

    private boolean isClosed = false;

    public PacketNumberSpace(PacketPhase phase) {
        this.phase = phase;
    }

    public void setConnectionPathController(ConnectionPathController connectionPathController) {
        this.connectionPathController = connectionPathController;
    }

    /**
     * Allocates the next packet number in this space.
     */
    public synchronized long allocatePacketNumber() {
        return nextPacketNumber++;
    }

    /**
     * Records that a packet was sent.
     * Stores the UNENCRYPTED payload and packet type for potential retransmission with a NEW packet number.
     * <p>
     * Per RFC 9002 Section 6.2: Retransmissions must use new packet numbers, so we store the
     * unencrypted frames to re-wrap them later with fresh encryption.
     *
     * @param packetNumber       The packet number
     * @param unencryptedPayload The unencrypted QUIC frames (for retransmission)
     * @param ackEliciting       Whether this packet requires an ACK
     * @param destinationAddress peer address
     */
    public void onPacketSent(long sentTime, long packetNumber, PoolBuffer unencryptedPayload, boolean ackEliciting, InetSocketAddress destinationAddress) {
        if (isClosed) {
            unencryptedPayload.release();
            logger.info("PacketNumberSpace is already closed");
            return;
        }

        if (!ackEliciting) {
            unencryptedPayload.release();
            return;
        }
        // Duplicate the buffer to preserve it for retransmission
        SentPacket packet = new SentPacket(packetNumber, sentTime, unencryptedPayload,
                phase, destinationAddress);
        sentPackets.put(packetNumber, packet);

        long initialLossDelay = MIN_LOSS_TIMEOUT;
        WindowedStatCounter windowedStatCounter = getWindowedStatCounter(destinationAddress);
        if (windowedStatCounter != null) {
            windowedStatCounter.totalSentBytes += packet.getSize();

            // Insert into the loss heap with an initial deadline based on the current RTT estimate.
            initialLossDelay = Math.max((long) (K_TIME_THRESHOLD * Math.max(windowedStatCounter.smoothedRtt, windowedStatCounter.latestRtt)), MIN_LOSS_TIMEOUT);
        }

        packet.lossDeadline = sentTime + initialLossDelay;
    }

    public WindowedStatCounter getWindowedStatCounter(InetSocketAddress destinationAddress) {
        if (connectionPathController == null) {
            return null;
        } else {
            ConnectionPath connectionPath = connectionPathController.getConnectionPath(destinationAddress);
            return connectionPath == null ? null : connectionPath.windowedStatCounter;
        }
    }

    /**
     * Records that a packet was received.
     */
    public synchronized void onPacketReceived(long timestampMs, long packetNumber, int ecnFlags) {
        receivedPackets.add((int) packetNumber);

        if (packetNumber > largestReceivedPacketNumber) {
            largestReceivedPacketNumber = packetNumber;
            largestReceivedPacketTimestamp = timestampMs;
        }

        boolean isCe = (ecnFlags & (1)) != 0;
        boolean isEct1 = (ecnFlags & (1 << 1)) != 0;
        boolean isEct0 = (ecnFlags & (1 << 2)) != 0;

        if (isCe) clientEctCeCounter++;
        if (isEct1) clientEct1Counter++;
        if (isEct0) clientEct0Counter++;

        logger.debug("{}: Received packet {}, largest: {}", phase, packetNumber, largestReceivedPacketNumber);
    }

    /**
     * Callback interface for processing acknowledged packets.
     */
    public interface AckCallback {
        void onPacketAcknowledged(long packetNumber, SentPacket packet);
    }

    /**
     * Processes received ACK frame and updates RTT, removes acked packets, detects losses.
     * RFC 9002 Section 6: Processing Acknowledgments
     *
     * @param timestampMs  Current timestamp
     * @param largestAcked Largest acknowledged packet number
     * @param ackRanges    List of acknowledged packet ranges
     * @param ackDelay     ACK delay in microseconds
     * @param ackCallback  Optional callback invoked for each acked packet before removal
     * @param ceCounter    ECN contingency event counter
     * @param sender       peer address
     */
    public int onAckReceived(long timestampMs, long largestAcked, List<AckRange> ackRanges, long ackDelay, AckCallback ackCallback, long ceCounter, SocketAddress sender) {
        logger.debug("{}: ACK received for largest: {}, ranges: {}", phase, largestAcked, ackRanges.size());

        WindowedStatCounter windowedStatCounter = getWindowedStatCounter((InetSocketAddress) sender);
        if (windowedStatCounter != null) {
            windowedStatCounter.onAckReceived(timestampMs, ceCounter);
        }

        // Update largest acked
        if (largestAcked > largestAckedPacketNumber) {
            largestAckedPacketNumber = largestAcked;
        }

        if (!ackRanges.isEmpty()) {
            firstAckedRangeLen = (int) (ackRanges.getFirst().largest - ackRanges.getFirst().smallest + 1);
        }

        // Find newly acked packets.
        // For each ACK range, subMap() seeks directly to the matching window in our TreeMap
        // in O(log n), then iterates only the entries that actually fall within it - O(log n + k).
        // We never enumerate packet numbers from the peer-supplied ranges themselves, so a
        // malicious enormous range costs nothing beyond a single O(log n) tree seek.
        Set<Long> newlyAcked = new HashSet<>();
        for (AckRange range : ackRanges) {
            newlyAcked.addAll(sentPackets.subMap(range.smallest, true, range.largest, true)
                    .keySet());
        }

        if (newlyAcked.isEmpty()) {
            logger.debug("{}: No newly acked packets", phase);
            return 0;
        }

        // Update RTT if largest acked is newly acked
        if (newlyAcked.contains(largestAcked)) {
            SentPacket packet = sentPackets.get(largestAcked);
            if (windowedStatCounter != null) {
                windowedStatCounter.updateRtt(timestampMs, packet.getSentTime(), ackDelay);
            }
        }

        int newlyAckedBytes = 0;

        // Process and remove acked packets
        for (long pn : newlyAcked) {
            SentPacket packet = sentPackets.remove(pn);
            if (packet != null) {
                newlyAckedBytes += packet.getSize();
                if (ackCallback != null) {
                    ackCallback.onPacketAcknowledged(pn, packet);
                }
                packet.getUnencryptedPayload().release();
            }
            logger.debug("{}: Packet {} acked and removed", phase, pn);
        }

        if (windowedStatCounter != null) {
            windowedStatCounter.updateAckStats(timestampMs, newlyAckedBytes, newlyAcked);
        }

        return newlyAckedBytes;
    }


    public void discardSentPackets() {
        isClosed = true;

        logger.info("Discarding sent packets {}", phase);
        for (SentPacket packet : sentPackets.values()) {
            packet.getUnencryptedPayload().release();
        }
        sentPackets.clear();
    }

    /**
     * Detects lost packets using time and packet thresholds (RFC 9002 Section 6.1).
     * Returns map of lost packet numbers to their SentPacket metadata for retransmission.
     * The caller will re-wrap the unencrypted payload with a NEW packet number.
     */
    public void detectLostPackets(long timestampMs, Function<SentPacket, Boolean> retransmit) {
        if (connectionPathController != null) {
            connectionPathController.clearOlderStats(timestampMs);
        }

        if (sentPackets.isEmpty()) {
            return;
        }

        // Packet threshold: declare lost if far enough below largest acked
        long lostPacketThreshold = largestAckedPacketNumber - kPacketThreshold;

        // --- Packet-threshold pass ---
        // headMap(lostPacketThreshold) returns only the entries with pn < lostPacketThreshold,
        // so we visit exactly the candidates without scanning the rest of the map.

        int num = 0;
        while (!sentPackets.isEmpty()) {
            Map.Entry<Long, SentPacket> entry = sentPackets.firstEntry();
            SentPacket packet = entry.getValue();
            if (entry.getKey() < lostPacketThreshold ||
                    packet.getTimeoutTimestamp() < timestampMs
            ) {
                if (retransmit.apply(packet)) {
                    sentPackets.pollFirstEntry();
                    WindowedStatCounter windowedStatCounter = getWindowedStatCounter(packet.getDestinationAddress());
                    if (windowedStatCounter != null) {
                        windowedStatCounter.onLostPacket(timestampMs, packet.getSize());
                        windowedStatCounter.totalSentBytes -= packet.getSize(); // do not add this to in-flight
                    }
                    num++;
                } else { // the queue is full
                    logger.info("{}: Retransmitted {} lost packets. Blocked by queue.", timestampMs, num);
                    return;
                }
            } else {
                break;
            }
        }
        if (num > 0) {
            if (timestampMs - lastLossDetectedMs < connectionPathController.getSmoothedRtt()) {
                kPacketThreshold = firstAckedRangeLen + 1;
            }
            lastLossDetectedMs = timestampMs;

            logger.info("Retransmitted {} lost packets.", num);
        } else {
            if (kPacketThreshold > MIN_K_PACKET_THRESHOLD) kPacketThreshold--;
        }
    }

    /**
     * Returns ACK ranges for received packets.
     * Used to construct ACK frames.
     */
    public SortedIntervals getAckRanges() {
        return receivedPackets;
    }

    public long getLargestReceivedPacketNumber() {
        return largestReceivedPacketNumber;
    }

    public long getAckDelay(long currentTimestampMs) {
        if (largestReceivedPacketTimestamp == -1) {
            return 0;
        }
        long delayUs = (currentTimestampMs - largestReceivedPacketTimestamp) * 1000;
        return delayUs >> 3; // default ack_delay_exponent = 3
    }

    public long getLargestAckedPacketNumber() {
        return largestAckedPacketNumber;
    }

    public boolean hasUnackedPackets() {
        return !sentPackets.isEmpty();
    }

    public int getUnackedPacketCount() {
        return sentPackets.size();
    }

    /**
     * Represents a range of acknowledged packet numbers.
     */
    public static class AckRange {
        public final long smallest;
        public final long largest;

        public AckRange(long smallest, long largest) {
            this.smallest = smallest;
            this.largest = largest;
        }

        @Override
        public String toString() {
            return "[" + smallest + "-" + largest + "]";
        }
    }

    /**
     * Metadata about a sent packet for loss detection and retransmission.
     * FIELD EXPLANATION (RFC 9002):
     * 1. packetNumber: The original packet number when this packet was first sent.
     * - Used for: ACK matching, loss detection thresholds, tracking
     * - NOT used for: Retransmission (retransmissions get NEW packet numbers)
     * 2. sentTime: Timestamp when packet was sent (milliseconds).
     * - Used for: RTT calculation, time-based loss detection
     * - Per RFC 9002 Section 6.1.2: packets sent before (now - loss_delay) are declared lost
     * 3. unencryptedPayload: The QUIC frames BEFORE encryption (CRYPTO, STREAM, ACK, etc.).
     * - Used for: Retransmission with a NEW packet number and NEW encryption
     * - Per RFC 9002 Section 6.2: "Packets that are declared lost are not retransmitted whole.
     * The same applies to frames that are never declared lost. Instead, the information
     * that might be carried in frames is sent again in new frames as needed."
     * - We store the frames (payload) so we can wrap them in a new packet with new PN
     * 4. packetType: Type of packet (INITIAL, HANDSHAKE, APPLICATION).
     * - Used for: Selecting correct encryption keys and header format during retransmission
     * - Different packet types use different key materials and header structures
     * 5. ackEliciting: Whether this packet requires an ACK from peer.
     * - Used for: RTT measurement (only ack-eliciting packets update RTT)
     * - Per RFC 9002 Section 5: ACK-only packets don't trigger ACKs or RTT updates
     *
     */
    public static class SentPacket {
        private final long packetNumber;
        private final long sentTime;
        final PoolBuffer unencryptedPayload;  // Frames BEFORE encryption (for retransmission)
        private final PacketPhase packetPhase;  // Packet type for re-wrapping
        private final InetSocketAddress destinationAddress;

        /**
         * Absolute loss deadline (ms since epoch): sentTime + lossDelay at insertion time.
         */
        long lossDeadline;

        SentPacket(long packetNumber, long sentTime, PoolBuffer unencryptedPayload,
                   PacketPhase packetPhase, InetSocketAddress destinationAddress) {
            this.packetNumber = packetNumber;
            this.sentTime = sentTime;
            this.unencryptedPayload = unencryptedPayload;
            this.packetPhase = packetPhase;
            this.destinationAddress = destinationAddress;
        }

        public PoolBuffer getUnencryptedPayload() {
            return unencryptedPayload;
        }

        public int getSize() {
            return unencryptedPayload.buf().remaining();
        }

        public long getTimeoutTimestamp() {
            return lossDeadline;
        }

        public long getPacketNumber() {
            return packetNumber;
        }

        public long getSentTime() {
            return sentTime;
        }

        public PacketPhase getPacketPhase() {
            return packetPhase;
        }

        public InetSocketAddress getDestinationAddress() {
            return destinationAddress;
        }
    }
}


