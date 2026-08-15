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

import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.struct.SortedIntervals;
import org.jquic.quic.struct.TimeoutHeap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Manages packet number space for a specific encryption level (Initial, Handshake, or Application).
 * Implements packet number allocation, ACK tracking, and loss detection per RFC 9000 and 9002.
 */
public class PacketNumberSpace {
    private static final Logger logger = LoggerFactory.getLogger(PacketNumberSpace.class);

    // RFC 9002: Loss detection constants
    private static final double K_TIME_THRESHOLD = 9.0 / 8.0; // 1.125
    private static final int K_PACKET_THRESHOLD = 3; // Packet reordering threshold
    private static final int K_GRANULARITY_MS = 1; // Timer granularity: 1ms
    private static final int K_INITIAL_RTT_MS = 333; // Initial RTT estimate: 333ms

    final PacketPhase phase; // For logging: "Initial", "Handshake", "Application"

    // Packet number allocation
    private long nextPacketNumber = 0;

    // Received packet tracking
    private long largestReceivedPacketNumber = -1;
    private long largestReceivedPacketTimestamp = -1;
    private final SortedIntervals receivedPackets = new SortedIntervals(255);

    // Sent packet tracking - TreeMap keeps packet numbers sorted so the packet-threshold
    // pass in detectLostPackets can use headMap() instead of scanning the full table.
    private final TreeMap<Long, SentPacket> sentPackets = new TreeMap<>();
    private long largestAckedPacketNumber = -1;

    // Bytes acked during last RTT tracking
    private long bytesAckedInLastRtt = 0;
    private int[] ackWindow = new int[32];
    private int[] lostWindow = new int[32];
    private long[] packetWindowCE = new long[32];
    private long lastTimeIdx = 0;

    private long serverCeCounter = -1;

    // RTT tracking (RFC 9002 Section 5)
    private int smoothedRtt = K_INITIAL_RTT_MS;
    private int rttVar = K_INITIAL_RTT_MS / 2;
    private int minRtt = Integer.MAX_VALUE;
    private int latestRtt = 0;
    private int timeWindowMs = 32;

    // Loss detection
    private long lossTime = 0; // Time at which next packet will be considered lost

    long clientEctCeCounter = 0;
    long clientEct0Counter = 0;
    long clientEct1Counter = 0;
    long intervalCePacketsThisWindow = 0;
    long bytesAckedThisWindow = 0;
    long packetsAckedThisWindow = 0;
    long bytesLostInWindow = 0;
    long bytesLostInLastRtt = 0;

    // Min-heap ordered by per-packet loss deadline for O(log n) loss detection.
    private final TimeoutHeap<SentPacket> lossHeap = new TimeoutHeap<>(SentPacket.class);

    public PacketNumberSpace(PacketPhase phase) {
        this.phase = phase;
    }

    /**
     * Allocates the next packet number in this space.
     */
    public synchronized long allocatePacketNumber() {
        return nextPacketNumber++;
    }

    public void setTimeWindowMs(int timeWindowMs) {
        if (timeWindowMs > 100) {
            throw  new IllegalArgumentException("timeWindowMs can't be greater than 100ms");
        }
        if (timeWindowMs > 32) {
            ackWindow = new int[timeWindowMs];
            lostWindow = new int[timeWindowMs];
            packetWindowCE = new long[timeWindowMs];
            this.timeWindowMs = timeWindowMs;
        }
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
     */
    public void onPacketSent(long sentTime, long packetNumber, PoolBuffer unencryptedPayload, boolean ackEliciting) {
        // Duplicate the buffer to preserve it for retransmission
        SentPacket packet = new SentPacket(packetNumber, sentTime, unencryptedPayload,
                phase, ackEliciting);
        sentPackets.put(packetNumber, packet);

        // Insert into the loss heap with an initial deadline based on the current RTT estimate.
        long initialLossDelay = Math.max(
                (long) (K_TIME_THRESHOLD * Math.max(smoothedRtt, latestRtt)),
                K_GRANULARITY_MS);

        packet.lossDeadline = sentTime + initialLossDelay;
        lossHeap.insertOrUpdate(packet);

        logger.debug("{}: Sent packet {} (ack-eliciting: {}, payload: {} bytes)",
                phase, packetNumber, ackEliciting, unencryptedPayload.buf().remaining());
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

        boolean isCe   = (ecnFlags & (1)) != 0;
        boolean isEct1 = (ecnFlags & (1 << 1)) != 0;
        boolean isEct0 = (ecnFlags & (1 << 2)) != 0;

        if (isCe)   clientEctCeCounter++;
        if (isEct1) clientEct1Counter++;
        if (isEct0) clientEct0Counter++;

        logger.debug("{}: Received packet {}, largest: {}", phase, packetNumber, largestReceivedPacketNumber);
    }

    /**
     * Packet type enumeration for identifying different QUIC .
     * Used for retransmission to re-wrap payloads with correct headers.
     */
    public enum PacketPhase {
        INITIAL,      // Initial packet (long header)
        HANDSHAKE,    // Handshake packet (long header)
        APPLICATION   // 1-RTT packet (short header)
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
     */
    public void onAckReceived(long timestampMs, long largestAcked, List<AckRange> ackRanges, long ackDelay, AckCallback ackCallback, long ceCounter) {
        logger.debug("{}: ACK received for largest: {}, ranges: {}", phase, largestAcked, ackRanges.size());

        if (serverCeCounter == -1) {
            serverCeCounter = ceCounter;
        }

        clearOldTimeBuckets(timestampMs);
        if (ceCounter > serverCeCounter) {
            long ceDelta = ceCounter - serverCeCounter;
            for (int i = 0; i < ceDelta; i++) {
                packetWindowCE[(int)(timestampMs % timeWindowMs)]++;
                intervalCePacketsThisWindow++;
            }
            serverCeCounter = ceCounter;
        }

        // Update largest acked
        if (largestAcked > largestAckedPacketNumber) {
            largestAckedPacketNumber = largestAcked;
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
            return;
        }

        // Update RTT if largest acked is newly acked
        if (newlyAcked.contains(largestAcked)) {
            SentPacket packet = sentPackets.get(largestAcked);
            if (packet != null && packet.ackEliciting) {
                updateRtt(timestampMs, packet.sentTime, ackDelay);
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
                lossHeap.remove(packet);
            }
            logger.debug("{}: Packet {} acked and removed", phase, pn);
        }

        // Update bytesAckedInLastRtt
        if (newlyAckedBytes > 0) {
            ackWindow[(int)(timestampMs % timeWindowMs)] += newlyAckedBytes;
            bytesAckedThisWindow += newlyAckedBytes;
            bytesAckedInLastRtt += newlyAckedBytes;
            packetsAckedThisWindow += newlyAcked.size();
        }
    }

    private void clearOldTimeBuckets(long timeIndex) {
        if (lastTimeIdx == 0) lastTimeIdx = timeIndex;
        if (lastTimeIdx != timeIndex) {
            for (long i = lastTimeIdx+1; i <= timeIndex; i++) {
                int rttEndIndex = (int)( (timeWindowMs + i - Math.min(smoothedRtt, timeWindowMs)) % timeWindowMs);
                bytesAckedInLastRtt -= ackWindow[rttEndIndex];
                bytesAckedThisWindow -= ackWindow[(int)(i % timeWindowMs)];
                bytesLostInLastRtt -= lostWindow[rttEndIndex];
                bytesLostInWindow -= lostWindow[(int)(i % timeWindowMs)];
                intervalCePacketsThisWindow -= packetWindowCE[(int)(i % timeWindowMs)];
                ackWindow[(int)(i % timeWindowMs)] = 0;
                lostWindow[(int)(i % timeWindowMs)] = 0;
                packetWindowCE[(int)(i % timeWindowMs)] = 0;
            }
            lastTimeIdx = timeIndex;
        }
    }

    /**
     * Updates RTT estimates based on ACK (RFC 9002 Section 5).
     * 
     * @param packetSentTime When the acked packet was sent
     * @param ackDelay ACK delay reported by peer (in microseconds)
     */
    private void updateRtt(long timestampMs, long packetSentTime, long ackDelay) {
        latestRtt = (int)(timestampMs - packetSentTime);

        // Adjust for ack delay (convert from microseconds to milliseconds)
        int adjustedRtt = latestRtt;
        if (latestRtt > minRtt + (ackDelay / 1000)) {
            adjustedRtt = latestRtt - (int)(ackDelay / 1000);
        }

        // Update min RTT
        if (latestRtt < minRtt) {
            minRtt = latestRtt;
        }

        // First RTT sample
        if (smoothedRtt == K_INITIAL_RTT_MS) {
            smoothedRtt = latestRtt;
            rttVar = latestRtt / 2;
        } else {
            // EWMA smoothing (RFC 9002 Section 5.3)
            int rttVarSample = Math.abs(smoothedRtt - adjustedRtt);
            rttVar = (3 * rttVar + rttVarSample) / 4;
            smoothedRtt = (7 * smoothedRtt + adjustedRtt) / 8;
        }

        logger.debug("{}: RTT updated - latest: {}ms, smoothed: {}ms, var: {}ms, min: {}ms",
                phase, latestRtt, smoothedRtt, rttVar, minRtt);
    }

    public void discardSentPackets() {
        if (!sentPackets.isEmpty()) {
            sentPackets.pollFirstEntry().getValue().getUnencryptedPayload().release();
        }
    }

    /**
     * Detects lost packets using time and packet thresholds (RFC 9002 Section 6.1).
     * Returns map of lost packet numbers to their SentPacket metadata for retransmission.
     * The caller will re-wrap the unencrypted payload with a NEW packet number.
     *
     * <p>Uses {@link #lossHeap} to find time-threshold candidates in O(log n) rather than
     * scanning all unacked packets. The packet-number threshold is still checked for every
     * candidate polled from the heap, and separately for all packets below the threshold.</p>
     */
    public java.util.Map<Long, SentPacket> detectLostPackets(long timestampMs) {
        java.util.Map<Long, SentPacket> lostPackets = new HashMap<>();

        clearOldTimeBuckets(timestampMs);

        if (sentPackets.isEmpty()) {
            return lostPackets;
        }

        // Calculate loss delay: max(time_threshold * max(smoothedRtt, latestRtt), kGranularity)
        long lossDelay = (long) (K_TIME_THRESHOLD * Math.max(smoothedRtt, latestRtt));
        lossDelay = Math.max(lossDelay, K_GRANULARITY_MS);

        // Packet threshold: declare lost if far enough below largest acked
        long lostPacketThreshold = largestAckedPacketNumber - K_PACKET_THRESHOLD;

        // --- Packet-threshold pass ---
        // headMap(lostPacketThreshold) returns only the entries with pn < lostPacketThreshold,
        // so we visit exactly the candidates without scanning the rest of the map.
        for (Map.Entry<Long, SentPacket> entry : sentPackets.headMap(lostPacketThreshold).entrySet()) {
            long pn = entry.getKey();
            SentPacket packet = entry.getValue();
            lostPackets.put(pn, packet);
            logger.info("{}: Packet {} declared lost (packet threshold: {} below largest acked {})",
                    phase, pn, largestAckedPacketNumber - pn, largestAckedPacketNumber);
        }

        // --- Time-threshold pass: poll heap entries whose deadline has passed ---
        // Each packet's deadline was fixed at send time using the RTT estimate current then.
        while (!lossHeap.isEmpty() && lossHeap.peek().getTimeoutTimestamp() <= timestampMs) {
            SentPacket packet = lossHeap.poll();
            // Guard: skip if already removed (acked) or above the ackable threshold.
            if (!sentPackets.containsKey(packet.packetNumber)) continue;
            if (packet.packetNumber >= largestAckedPacketNumber) continue;
            lostPackets.put(packet.packetNumber, packet);
            logger.info("{}: Packet {} declared lost (time threshold: sent {}ms ago, threshold: {}ms)",
                    phase, packet.packetNumber, timestampMs - packet.sentTime, lossDelay);
        }

        // Remove lost packets from tracking (heap entries already removed by poll above;
        // packet-threshold losses need explicit heap removal).
        for (Map.Entry<Long, SentPacket> entry : lostPackets.entrySet()) {
            sentPackets.remove(entry.getKey());
            if (entry.getValue().getTimeoutHeapIndex() != -1) {
                lossHeap.remove(entry.getValue());
            }
        }

        // Update loss time: the next expiry is simply the heap minimum - O(1).
        SentPacket next = lossHeap.peek();
        lossTime = (next != null) ? next.getTimeoutTimestamp() : 0;

        for (SentPacket packet : lostPackets.values()) {
            lostWindow[(int)(timestampMs % timeWindowMs)] += packet.unencryptedPayload.buf().remaining();
            bytesLostInWindow += packet.unencryptedPayload.buf().remaining();
            bytesAckedInLastRtt += packet.unencryptedPayload.buf().remaining();
        }

        return lostPackets;
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

    public long getPTO() {
        return smoothedRtt + 4L * rttVar;
    }

    public long getSmoothedRtt() {
        return smoothedRtt;
    }

    public long getLatestRtt() {
        return latestRtt;
    }

    public long getMinRtt() {
        return minRtt;
    }

    public long getLossTime() {
        return lossTime;
    }

    public long getServerCeCounter() {
        return serverCeCounter;
    }

    public record WindowedStats(
            long intervalCePackets,
            long bytesAcked,
            long packetsAcked,
            long bytesLost,
            long bytesAckedInLastRtt,
            long bytesLostInLastRtt
    ) {}

    public WindowedStats getWindowedStats() {
        return new WindowedStats(
                intervalCePacketsThisWindow,
                bytesAckedThisWindow,
                packetsAckedThisWindow,
                bytesLostInWindow,
                smoothedRtt <= timeWindowMs ? bytesAckedInLastRtt : (bytesAckedInLastRtt / timeWindowMs) * smoothedRtt,
                smoothedRtt <= timeWindowMs ? bytesLostInLastRtt : (bytesLostInLastRtt / timeWindowMs) * smoothedRtt
        );
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
     *    - Used for: ACK matching, loss detection thresholds, tracking
     *    - NOT used for: Retransmission (retransmissions get NEW packet numbers)
     * 2. sentTime: Timestamp when packet was sent (milliseconds).
     *    - Used for: RTT calculation, time-based loss detection
     *    - Per RFC 9002 Section 6.1.2: packets sent before (now - loss_delay) are declared lost
     * 3. unencryptedPayload: The QUIC frames BEFORE encryption (CRYPTO, STREAM, ACK, etc.).
     *    - Used for: Retransmission with a NEW packet number and NEW encryption
     *    - Per RFC 9002 Section 6.2: "Packets that are declared lost are not retransmitted whole.
     *      The same applies to frames that are never declared lost. Instead, the information
     *      that might be carried in frames is sent again in new frames as needed."
     *    - We store the frames (payload) so we can wrap them in a new packet with new PN
     * 4. packetType: Type of packet (INITIAL, HANDSHAKE, APPLICATION).
     *    - Used for: Selecting correct encryption keys and header format during retransmission
     *    - Different packet types use different key materials and header structures
     * 5. ackEliciting: Whether this packet requires an ACK from peer.
     *    - Used for: RTT measurement (only ack-eliciting packets update RTT)
     *    - Per RFC 9002 Section 5: ACK-only packets don't trigger ACKs or RTT updates
     * 
     */
    public static class SentPacket implements TimeoutHeap.Entry {
        final long packetNumber;
        final long sentTime;
        final PoolBuffer unencryptedPayload;  // Frames BEFORE encryption (for retransmission)
        final PacketPhase packetPhase;  // Packet type for re-wrapping
        final boolean ackEliciting;

        /** Absolute loss deadline (ms since epoch): sentTime + lossDelay at insertion time. */
        long lossDeadline;
        /** Position in the {@link TimeoutHeap}; -1 when not currently in the heap. */
        private int heapIndex = -1;

        SentPacket(long packetNumber, long sentTime, PoolBuffer unencryptedPayload,
                   PacketPhase packetPhase, boolean ackEliciting) {
            this.packetNumber = packetNumber;
            this.sentTime = sentTime;
            this.unencryptedPayload = unencryptedPayload;
            this.packetPhase = packetPhase;
            this.ackEliciting = ackEliciting;
        }

        public PoolBuffer getUnencryptedPayload() {
            return unencryptedPayload;
        }

        public int getSize() {
            return unencryptedPayload.buf().remaining();
        }

        // ---- TimeoutHeap.Entry ----

        @Override
        public int getTimeoutHeapIndex() {
            return heapIndex;
        }

        @Override
        public void setTimeoutHeapIndex(int idx) {
            this.heapIndex = idx;
        }

        /** Returns the loss deadline used to order this packet in the {@link TimeoutHeap}. */
        @Override
        public long getTimeoutTimestamp() {
            return lossDeadline;
        }
    }
}


