package org.fmalyshev.quic;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.*;

/**
 * Manages packet number space for a specific encryption level (Initial, Handshake, or Application).
 * Implements packet number allocation, ACK tracking, and loss detection per RFC 9000 & 9002.
 */
public class PacketNumberSpace {
    private static final Logger logger = LoggerFactory.getLogger(PacketNumberSpace.class);

    // RFC 9002: Loss detection constants
    private static final double K_TIME_THRESHOLD = 9.0 / 8.0; // 1.125
    private static final long K_PACKET_THRESHOLD = 3; // Packet reordering threshold
    private static final long K_GRANULARITY_MS = 1; // Timer granularity: 1ms
    private static final long K_INITIAL_RTT_MS = 333; // Initial RTT estimate: 333ms

    final PacketPhase phase; // For logging: "Initial", "Handshake", "Application"

    // Packet number allocation
    private long nextPacketNumber = 0;

    // Received packet tracking
    private long largestReceivedPacketNumber = -1;
    private final Set<Long> receivedPackets = new TreeSet<>();

    // Sent packet tracking — TreeMap keeps packet numbers sorted so the packet-threshold
    // pass in detectLostPackets can use headMap() instead of scanning the full table.
    private final TreeMap<Long, SentPacket> sentPackets = new TreeMap<>();
    private long largestAckedPacketNumber = -1;

    // RTT tracking (RFC 9002 Section 5)
    private long smoothedRtt = K_INITIAL_RTT_MS;
    private long rttVar = K_INITIAL_RTT_MS / 2;
    private long minRtt = Long.MAX_VALUE;
    private long latestRtt = 0;

    // Loss detection
    private long lossTime = 0; // Time at which next packet will be considered lost
    private long lastAckElicitingSentTime = 0;

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

    /**
     * Records that a packet was sent.
     * Stores the UNENCRYPTED payload and packet type for potential retransmission with a NEW packet number.
     * 
     * Per RFC 9002 Section 6.2: Retransmissions must use new packet numbers, so we store the
     * unencrypted frames to re-wrap them later with fresh encryption.
     * 
     * @param packetNumber The packet number
     * @param unencryptedPayload The unencrypted QUIC frames (for retransmission)
     * @param ackEliciting Whether this packet requires an ACK
     */
    public void onPacketSent(long packetNumber, ByteBuffer unencryptedPayload, boolean ackEliciting) {
        long sentTime = System.currentTimeMillis();
        // Duplicate the buffer to preserve it for retransmission
        SentPacket packet = new SentPacket(packetNumber, sentTime, unencryptedPayload.duplicate(),
                phase, ackEliciting);
        sentPackets.put(packetNumber, packet);

        if (ackEliciting) {
            lastAckElicitingSentTime = sentTime;
        }

        // Insert into the loss heap with an initial deadline based on the current RTT estimate.
        long initialLossDelay = Math.max(
                (long) (K_TIME_THRESHOLD * Math.max(smoothedRtt, latestRtt)),
                K_GRANULARITY_MS);
        packet.lossDeadline = sentTime + initialLossDelay;
        lossHeap.insertOrUpdate(packet);

        logger.debug("{}: Sent packet {} (ack-eliciting: {}, payload: {} bytes)",
                phase, packetNumber, ackEliciting, unencryptedPayload.remaining());
    }

    /**
     * Records that a packet was received.
     */
    public synchronized void onPacketReceived(long packetNumber) {
        receivedPackets.add(packetNumber);

        if (packetNumber > largestReceivedPacketNumber) {
            largestReceivedPacketNumber = packetNumber;
        }

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
     * @param largestAcked Largest acknowledged packet number
     * @param ackRanges List of acknowledged packet ranges
     * @param ackDelay ACK delay in microseconds
     * @param ackCallback Optional callback invoked for each acked packet before removal
     * @return Map of lost packet numbers to SentPacket metadata (for retransmission with new PN)
     */
    public void onAckReceived(long largestAcked, List<AckRange> ackRanges, long ackDelay, AckCallback ackCallback) {
        logger.info("{}: ACK received for largest: {}, ranges: {}", phase, largestAcked, ackRanges.size());

        // Update largest acked
        if (largestAcked > largestAckedPacketNumber) {
            largestAckedPacketNumber = largestAcked;
        }

        // Find newly acked packets.
        // For each ACK range, subMap() seeks directly to the matching window in our TreeMap
        // in O(log n), then iterates only the entries that actually fall within it — O(log n + k).
        // We never enumerate packet numbers from the peer-supplied ranges themselves, so a
        // malicious enormous range costs nothing beyond a single O(log n) tree seek.
        Set<Long> newlyAcked = new HashSet<>();
        for (AckRange range : ackRanges) {
            sentPackets.subMap(range.smallest, true, range.largest, true)
                       .keySet()
                       .forEach(newlyAcked::add);
        }

        if (newlyAcked.isEmpty()) {
            logger.debug("{}: No newly acked packets", phase);
            return;
        }

        // Update RTT if largest acked is newly acked
        if (newlyAcked.contains(largestAcked)) {
            SentPacket packet = sentPackets.get(largestAcked);
            if (packet != null && packet.ackEliciting) {
                updateRtt(packet.sentTime, ackDelay);
            }
        }

        // Process and remove acked packets
        for (long pn : newlyAcked) {
            SentPacket packet = sentPackets.get(pn);
            if (packet != null) {
                if (ackCallback != null) {
                    ackCallback.onPacketAcknowledged(pn, packet);
                }
                lossHeap.remove(packet);
            }
            sentPackets.remove(pn);
            logger.debug("{}: Packet {} acked and removed", phase, pn);
        }
    }

    /**
     * Updates RTT estimates based on ACK (RFC 9002 Section 5).
     * 
     * @param packetSentTime When the acked packet was sent
     * @param ackDelay ACK delay reported by peer (in microseconds)
     */
    private void updateRtt(long packetSentTime, long ackDelay) {
        long now = System.currentTimeMillis();
        latestRtt = now - packetSentTime;

        // Adjust for ack delay (convert from microseconds to milliseconds)
        long adjustedRtt = latestRtt;
        if (latestRtt > minRtt + (ackDelay / 1000)) {
            adjustedRtt = latestRtt - (ackDelay / 1000);
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
            long rttVarSample = Math.abs(smoothedRtt - adjustedRtt);
            rttVar = (3 * rttVar + rttVarSample) / 4;
            smoothedRtt = (7 * smoothedRtt + adjustedRtt) / 8;
        }

        logger.debug("{}: RTT updated - latest: {}ms, smoothed: {}ms, var: {}ms, min: {}ms",
                phase, latestRtt, smoothedRtt, rttVar, minRtt);
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
    public java.util.Map<Long, SentPacket> detectLostPackets() {
        java.util.Map<Long, SentPacket> lostPackets = new HashMap<>();

        if (sentPackets.isEmpty()) {
            return lostPackets;
        }

        long now = System.currentTimeMillis();

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
            logger.warn("{}: Packet {} declared lost (packet threshold: {} below largest acked {})",
                    phase, pn, largestAckedPacketNumber - pn, largestAckedPacketNumber);
        }

        // --- Time-threshold pass: poll heap entries whose deadline has passed ---
        // Each packet's deadline was fixed at send time using the RTT estimate current then.
        while (!lossHeap.isEmpty() && lossHeap.peek().getTimeoutTimestamp() <= now) {
            SentPacket packet = lossHeap.poll();
            // Guard: skip if already removed (acked) or above the ackable threshold.
            if (!sentPackets.containsKey(packet.packetNumber)) continue;
            if (packet.packetNumber >= largestAckedPacketNumber) continue;
            lostPackets.put(packet.packetNumber, packet);
            logger.warn("{}: Packet {} declared lost (time threshold: sent {}ms ago, threshold: {}ms)",
                    phase, packet.packetNumber, now - packet.sentTime, lossDelay);
        }

        // Remove lost packets from tracking (heap entries already removed by poll above;
        // packet-threshold losses need explicit heap removal).
        for (Map.Entry<Long, SentPacket> entry : lostPackets.entrySet()) {
            sentPackets.remove(entry.getKey());
            if (entry.getValue().getTimeoutHeapIndex() != -1) {
                lossHeap.remove(entry.getValue());
            }
        }

        // Update loss time: the next expiry is simply the heap minimum — O(1).
        SentPacket next = lossHeap.peek();
        lossTime = (next != null) ? next.getTimeoutTimestamp() : 0;

        return lostPackets;
    }

    /**
     * Returns ACK ranges for received packets.
     * Used to construct ACK frames.
     */
    public List<AckRange> getAckRanges() {
        if (receivedPackets.isEmpty()) {
            return Collections.emptyList();
        }

        List<AckRange> ranges = new ArrayList<>();
        List<Long> sorted = new ArrayList<>(receivedPackets);
        Collections.sort(sorted, Collections.reverseOrder());

        long rangeStart = sorted.get(0);
        long rangeEnd = sorted.get(0);

        for (int i = 1; i < sorted.size(); i++) {
            long pn = sorted.get(i);

            if (pn == rangeEnd - 1) {
                // Contiguous, extend range
                rangeEnd = pn;
            } else {
                // Gap found, save current range and start new one
                ranges.add(new AckRange(rangeEnd, rangeStart));
                rangeStart = pn;
                rangeEnd = pn;
            }
        }

        // Add final range
        ranges.add(new AckRange(rangeEnd, rangeStart));

        return ranges;
    }

    public long getLargestReceivedPacketNumber() {
        return largestReceivedPacketNumber;
    }

    public long getPTO() {
        return smoothedRtt + 4 * rttVar;
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
     * 
     * FIELD EXPLANATION (RFC 9002):
     * 
     * 1. packetNumber: The original packet number when this packet was first sent.
     *    - Used for: ACK matching, loss detection thresholds, tracking
     *    - NOT used for: Retransmission (retransmissions get NEW packet numbers)
     * 
     * 2. sentTime: Timestamp when packet was sent (milliseconds).
     *    - Used for: RTT calculation, time-based loss detection
     *    - Per RFC 9002 Section 6.1.2: packets sent before (now - loss_delay) are declared lost
     * 
     * 3. unencryptedPayload: The QUIC frames BEFORE encryption (CRYPTO, STREAM, ACK, etc.).
     *    - Used for: Retransmission with a NEW packet number and NEW encryption
     *    - Per RFC 9002 Section 6.2: "Packets that are declared lost are not retransmitted whole.
     *      The same applies to frames that are never declared lost. Instead, the information
     *      that might be carried in frames is sent again in new frames as needed."
     *    - We store the frames (payload) so we can wrap them in a new packet with new PN
     * 
     * 4. packetType: Type of packet (INITIAL, HANDSHAKE, APPLICATION).
     *    - Used for: Selecting correct encryption keys and header format during retransmission
     *    - Different packet types use different key materials and header structures
     * 
     * 5. ackEliciting: Whether this packet requires an ACK from peer.
     *    - Used for: RTT measurement (only ack-eliciting packets update RTT)
     *    - Per RFC 9002 Section 5: ACK-only packets don't trigger ACKs or RTT updates
     * 
     */
    public static class SentPacket implements TimeoutHeap.Entry {
        final long packetNumber;
        final long sentTime;
        final ByteBuffer unencryptedPayload;  // Frames BEFORE encryption (for retransmission)
        final PacketPhase packetPhase;  // Packet type for re-wrapping
        final boolean ackEliciting;

        /** Absolute loss deadline (ms since epoch): sentTime + lossDelay at insertion time. */
        long lossDeadline;
        /** Position in the {@link TimeoutHeap}; -1 when not currently in the heap. */
        private int heapIndex = -1;

        SentPacket(long packetNumber, long sentTime, ByteBuffer unencryptedPayload,
                   PacketPhase packetPhase, boolean ackEliciting) {
            this.packetNumber = packetNumber;
            this.sentTime = sentTime;
            this.unencryptedPayload = unencryptedPayload;
            this.packetPhase = packetPhase;
            this.ackEliciting = ackEliciting;
        }

        public ByteBuffer getUnencryptedPayload() {
            return unencryptedPayload;
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

