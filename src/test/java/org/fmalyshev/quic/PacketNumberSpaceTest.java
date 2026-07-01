package org.fmalyshev.quic;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for PacketNumberSpace - packet number management, ACK processing, loss detection.
 */
class PacketNumberSpaceTest {

    @Test
    void testAllocatePacketNumber_Sequential() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        assertEquals(0, space.allocatePacketNumber());
        assertEquals(1, space.allocatePacketNumber());
        assertEquals(2, space.allocatePacketNumber());
        assertEquals(3, space.allocatePacketNumber());
    }

    @Test
    void testOnPacketReceived_TracksLargest() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        space.onPacketReceived(5);
        assertEquals(5, space.getLargestReceivedPacketNumber());

        space.onPacketReceived(3);
        assertEquals(5, space.getLargestReceivedPacketNumber());

        space.onPacketReceived(10);
        assertEquals(10, space.getLargestReceivedPacketNumber());
    }

    @Test
    void testOnPacketSent_TracksPackets() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);
        ByteBuffer frames = ByteBuffer.wrap(new byte[10]);

        space.onPacketSent(0, frames,  true);
        space.onPacketSent(1, frames,  true);

        assertEquals(2, space.getUnackedPacketCount());
        assertTrue(space.hasUnackedPackets());
    }

    @Test
    void testOnAckReceived_RemovesAckedPackets() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);
        ByteBuffer frames = ByteBuffer.wrap(new byte[10]);

        // Send packets 0, 1, 2
        space.onPacketSent(0, frames,  true);
        space.onPacketSent(1, frames,  true);
        space.onPacketSent(2, frames,  true);

        assertEquals(3, space.getUnackedPacketCount());

        // ACK packets 0 and 1
        List<PacketNumberSpace.AckRange> ackRanges = Arrays.asList(
            new PacketNumberSpace.AckRange(0, 1)
        );
        space.onAckReceived(1, ackRanges, 0, null);
        java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = space.detectLostPackets();

        // Only packet 2 should remain
        assertEquals(1, space.getUnackedPacketCount());
        assertTrue(lostPackets.isEmpty(), "No packets should be lost yet");
    }

    @Test
    void testOnAckReceived_UpdatesRTT() throws InterruptedException {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);
        ByteBuffer frames = ByteBuffer.wrap(new byte[10]);

        // Send packet 0
        space.onPacketSent(0, frames,  true);

        // Wait a bit to simulate network delay
        Thread.sleep(50);

        // ACK packet 0
        List<PacketNumberSpace.AckRange> ackRanges = Arrays.asList(
            new PacketNumberSpace.AckRange(0, 0)
        );
        space.onAckReceived(0, ackRanges, 0, null);
        java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = space.detectLostPackets();

        // RTT should be updated
        long rtt = space.getLatestRtt();
        assertTrue(rtt >= 50, "RTT should be at least 50ms, got: " + rtt);
        assertTrue(rtt < 1000, "RTT should be reasonable, got: " + rtt);
        assertTrue(lostPackets.isEmpty(), "No packets should be lost");
    }

    @Test
    void testDetectLostPackets_PacketThreshold() throws InterruptedException {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);
        ByteBuffer frames = ByteBuffer.wrap(new byte[10]);

        // Send packets 0-10
        for (int i = 0; i <= 10; i++) {
            space.onPacketSent(i, frames,  true);
        }

        Thread.sleep(10);

        // ACK packet 10 (leaving 0-9 unacked)
        List<PacketNumberSpace.AckRange> ackRanges = Arrays.asList(
            new PacketNumberSpace.AckRange(10, 10)
        );
        space.onAckReceived(10, ackRanges, 0, null);
        java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = space.detectLostPackets();

        // Packets 0-6 should be declared lost (more than 3 below largest acked)
        assertTrue(lostPackets.containsKey(0L), "Packet 0 should be lost");
        assertTrue(lostPackets.containsKey(6L), "Packet 6 should be lost");
        assertFalse(lostPackets.containsKey(7L), "Packet 7 should not be lost (within threshold)");
        assertFalse(lostPackets.containsKey(8L), "Packet 8 should not be lost");
        assertFalse(lostPackets.containsKey(9L), "Packet 9 should not be lost");
    }

    @Test
    void testDetectLostPackets_TimeThreshold() throws InterruptedException {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);
        ByteBuffer frames = ByteBuffer.wrap(new byte[10]);

        // Send packet 0
        space.onPacketSent(0, frames,  true);


        // Send and ACK packet 1 to establish RTT
        space.onPacketSent(1, frames,  true);

        // Wait for RTT to pass
        Thread.sleep(200);

        List<PacketNumberSpace.AckRange> ackRanges1 = Arrays.asList(
            new PacketNumberSpace.AckRange(1, 1)
        );
        space.onAckReceived(1, ackRanges1, 0, null);


        // Send and ACK packet 2 to trigger loss detection for packet 0
        space.onPacketSent(2, frames,  true);

        // Wait for loss delay threshold (9/8 * RTT)
        Thread.sleep(300);
        List<PacketNumberSpace.AckRange> ackRanges2 = Arrays.asList(
            new PacketNumberSpace.AckRange(2, 2)
        );
        space.onAckReceived(2, ackRanges2, 0, null);
        java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = space.detectLostPackets();

        // Packet 0 should be lost due to time threshold
        assertTrue(lostPackets.containsKey(0L), "Packet 0 should be lost due to time threshold");
    }

    @Test
    void testGetAckRanges_SingleRange() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        // Receive contiguous packets 0-4
        for (long i = 0; i <= 4; i++) {
            space.onPacketReceived(i);
        }

        List<PacketNumberSpace.AckRange> ranges = space.getAckRanges();

        assertEquals(1, ranges.size());
        assertEquals(0, ranges.get(0).smallest);
        assertEquals(4, ranges.get(0).largest);
    }

    @Test
    void testGetAckRanges_MultipleRanges() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        // Receive packets with gaps: 0-2, 5-7, 10
        space.onPacketReceived(0);
        space.onPacketReceived(1);
        space.onPacketReceived(2);
        space.onPacketReceived(5);
        space.onPacketReceived(6);
        space.onPacketReceived(7);
        space.onPacketReceived(10);

        List<PacketNumberSpace.AckRange> ranges = space.getAckRanges();

        assertEquals(3, ranges.size());

        // Ranges should be in descending order (largest first)
        assertEquals(10, ranges.get(0).smallest);
        assertEquals(10, ranges.get(0).largest);

        assertEquals(5, ranges.get(1).smallest);
        assertEquals(7, ranges.get(1).largest);

        assertEquals(0, ranges.get(2).smallest);
        assertEquals(2, ranges.get(2).largest);
    }

    @Test
    void testGetAckRanges_OutOfOrderReceipt() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        // Receive packets out of order
        space.onPacketReceived(5);
        space.onPacketReceived(2);
        space.onPacketReceived(8);
        space.onPacketReceived(3);
        space.onPacketReceived(4);

        List<PacketNumberSpace.AckRange> ranges = space.getAckRanges();

        // Should merge into ranges: [8], [2-5]
        assertEquals(2, ranges.size());
        assertTrue(ranges.stream().anyMatch(r -> r.smallest == 8 && r.largest == 8));
        assertTrue(ranges.stream().anyMatch(r -> r.smallest == 2 && r.largest == 5));
    }

    @Test
    void testRTT_InitialValue() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        // Initial RTT should be 333ms per RFC 9002
        assertEquals(333, space.getSmoothedRtt());
    }

    @Test
    void testRTT_MinRttTracking() throws InterruptedException {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);
        ByteBuffer frames = ByteBuffer.wrap(new byte[10]);

        // Send multiple packets and ACK them with different delays
        for (int i = 0; i < 3; i++) {
            space.onPacketSent(i, frames,  true);
            Thread.sleep(10 + i * 10); // Increasing delays

            List<PacketNumberSpace.AckRange> ackRanges = Arrays.asList(
                new PacketNumberSpace.AckRange(i, i)
            );
            space.onAckReceived(i, ackRanges, 0, null);
            java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = space.detectLostPackets();
            assertTrue(lostPackets.isEmpty(), "No packets should be lost during RTT tracking");
        }

        // Min RTT should be close to the first (shortest) sample
        long minRtt = space.getMinRtt();
        assertTrue(minRtt >= 10, "Min RTT should be at least 10ms");
        assertTrue(minRtt <= 50, "Min RTT should capture minimum delay");
    }

    @Test
    void testHasUnackedPackets_Empty() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        assertFalse(space.hasUnackedPackets());
        assertEquals(0, space.getUnackedPacketCount());
    }

    @Test
    void testAckEliciting_NonAckElicitingPackets() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);
        ByteBuffer frames = ByteBuffer.wrap(new byte[10]);

        // Send non-ack-eliciting packet (e.g., ACK-only packet)
        space.onPacketSent(0, frames, false);

        // ACK it
        List<PacketNumberSpace.AckRange> ackRanges = Arrays.asList(
            new PacketNumberSpace.AckRange(0, 0)
        );
        space.onAckReceived(0, ackRanges, 0, null);
        java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = space.detectLostPackets();

        // RTT should still be initial value since packet wasn't ack-eliciting
        assertEquals(333, space.getSmoothedRtt());
        assertTrue(lostPackets.isEmpty(), "No packets should be lost");
    }
}
