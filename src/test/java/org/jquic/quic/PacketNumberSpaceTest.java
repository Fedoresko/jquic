package org.jquic.quic;

import org.jquic.quic.buffers.BufferPool;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.buffers.RootPoolBuffer;
import org.jquic.quic.struct.SortedIntervals;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

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

        space.onPacketReceived(5, 0);
        assertEquals(5, space.getLargestReceivedPacketNumber());

        space.onPacketReceived(3, 0);
        assertEquals(5, space.getLargestReceivedPacketNumber());

        space.onPacketReceived(10, 0);
        assertEquals(10, space.getLargestReceivedPacketNumber());
    }

    @Test
    void testOnPacketSent_TracksPackets() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);
        PoolBuffer frames = new RootPoolBuffer(ByteBuffer.allocate(10), mock(BufferPool.class), false);

        space.onPacketSent(0, 0, frames,  true);
        space.onPacketSent(0, 1, frames,  true);

        assertEquals(2, space.getUnackedPacketCount());
        assertTrue(space.hasUnackedPackets());
    }

    @Test
    void testOnAckReceived_RemovesAckedPackets() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        // Send packets 0, 1, 2
        space.onPacketSent(0, 0, new RootPoolBuffer(ByteBuffer.allocate(10), mock(BufferPool.class), false).borrow(),  true);
        space.onPacketSent(0, 1, new RootPoolBuffer(ByteBuffer.allocate(10), mock(BufferPool.class), false).borrow(),  true);
        space.onPacketSent(0, 2, new RootPoolBuffer(ByteBuffer.allocate(10), mock(BufferPool.class), false).borrow(),  true);

        assertEquals(3, space.getUnackedPacketCount());

        // ACK packets 0 and 1
        List<PacketNumberSpace.AckRange> ackRanges = Arrays.asList(
            new PacketNumberSpace.AckRange(0, 1)
        );
        space.onAckReceived(0, 1, ackRanges, 0, null, 0);
        java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = space.detectLostPackets(0);

        // Only packet 2 should remain
        assertEquals(1, space.getUnackedPacketCount());
        assertTrue(lostPackets.isEmpty(), "No packets should be lost yet");
    }

    @Test
    void testOnAckReceived_UpdatesRTT() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        // Send packet 0 at T=0
        space.onPacketSent(0, 0, new RootPoolBuffer(ByteBuffer.allocate(10), mock(BufferPool.class), false).borrow(),  true);

        // ACK packet 0 at T=50
        List<PacketNumberSpace.AckRange> ackRanges = Arrays.asList(
            new PacketNumberSpace.AckRange(0, 0)
        );
        space.onAckReceived(50, 0, ackRanges, 0, null, 0);
        java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = space.detectLostPackets(50);

        // RTT should be updated
        long rtt = space.getLatestRtt();
        assertEquals(50, rtt, "RTT should be exactly 50ms, got: " + rtt);
        assertTrue(lostPackets.isEmpty(), "No packets should be lost");
    }

    @Test
    void testDetectLostPackets_PacketThreshold() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        // Send packets 0-10 at T=0
        for (int i = 0; i <= 10; i++) {
            space.onPacketSent(0, i, new RootPoolBuffer(ByteBuffer.allocate(10), mock(BufferPool.class), false).borrow(),  true);
        }

        // ACK packet 10 at T=10 (leaving 0-9 unacked)
        List<PacketNumberSpace.AckRange> ackRanges = Arrays.asList(
            new PacketNumberSpace.AckRange(10, 10)
        );
        space.onAckReceived(10, 10, ackRanges, 0, null, 0);
        java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = space.detectLostPackets(10);

        // Packets 0-6 should be declared lost (more than 3 below largest acked)
        assertTrue(lostPackets.containsKey(0L), "Packet 0 should be lost");
        assertTrue(lostPackets.containsKey(6L), "Packet 6 should be lost");
        assertFalse(lostPackets.containsKey(7L), "Packet 7 should not be lost (within threshold)");
        assertFalse(lostPackets.containsKey(8L), "Packet 8 should not be lost");
        assertFalse(lostPackets.containsKey(9L), "Packet 9 should not be lost");
    }

    @Test
    void testDetectLostPackets_TimeThreshold() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        // Send packet 0 at T=0
        space.onPacketSent(0, 0, new RootPoolBuffer(ByteBuffer.allocate(10), mock(BufferPool.class), false).borrow(),  true);

        // Send and ACK packet 1 at T=100 to establish RTT=100
        space.onPacketSent(100, 1, new RootPoolBuffer(ByteBuffer.allocate(10), mock(BufferPool.class), false).borrow(),  true);
        List<PacketNumberSpace.AckRange> ackRanges1 = Arrays.asList(
            new PacketNumberSpace.AckRange(1, 1)
        );
        space.onAckReceived(200, 1, ackRanges1, 0, null, 0);

        // Send and ACK packet 2 at T=300 to trigger loss detection for packet 0
        space.onPacketSent(300, 2, new RootPoolBuffer(ByteBuffer.allocate(10), mock(BufferPool.class), false).borrow(),  true);
        List<PacketNumberSpace.AckRange> ackRanges2 = Arrays.asList(
            new PacketNumberSpace.AckRange(2, 2)
        );
        space.onAckReceived(400, 2, ackRanges2, 0, null, 0);
        
        // Wait for loss delay threshold (9/8 * RTT)
        // RTT is ~100ms. Loss delay is 125ms.
        // Packet 0 sent at 0. Deadline was ~125. At T=400 it should be lost.
        java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = space.detectLostPackets(400);

        // Packet 0 should be lost due to time threshold
        assertTrue(lostPackets.containsKey(0L), "Packet 0 should be lost due to time threshold");
    }

    @Test
    void testGetAckRanges_SingleRange() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        // Receive contiguous packets 0-4
        for (long i = 0; i <= 4; i++) {
            space.onPacketReceived(i, 0);
        }

        SortedIntervals ranges = space.getAckRanges();

        SortedIntervals.Interval first = ranges.iterator().next();

        assertEquals(1, ranges.size());
        assertEquals(0, first.lower());
        assertEquals(4, first.higher());
    }

    @Test
    void testGetAckRanges_MultipleRanges() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        // Receive packets with gaps: 0-2, 5-7, 10
        space.onPacketReceived(0, 0);
        space.onPacketReceived(1, 0);
        space.onPacketReceived(2, 0);
        space.onPacketReceived(5, 0);
        space.onPacketReceived(6, 0);
        space.onPacketReceived(7, 0);
        space.onPacketReceived(10, 0);

        SortedIntervals ranges = space.getAckRanges();

        assertEquals(3, ranges.size());

        Iterator<SortedIntervals.Interval> it = space.getAckRanges().iterator();

        SortedIntervals.Interval next = it.next();
        // Ranges should be in descending order (largest first)
        assertEquals(10, next.lower());
        assertEquals(10, next.higher());

        next = it.next();
        assertEquals(5, next.lower());
        assertEquals(7, next.higher());

        next = it.next();
        assertEquals(0, next.lower());
        assertEquals(2, next.higher());
    }

    @Test
    void testGetAckRanges_OutOfOrderReceipt() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        // Receive packets out of order
        space.onPacketReceived(5, 0);
        space.onPacketReceived(2, 0);
        space.onPacketReceived(8, 0);
        space.onPacketReceived(3, 0);
        space.onPacketReceived(4, 0);

        SortedIntervals ranges = space.getAckRanges();


        // Should merge into ranges: [8], [2-5]
        assertEquals(2, ranges.size());
        assertTrue(StreamSupport.stream(ranges.spliterator(), false).anyMatch(r -> r.lower() == 8 && r.higher() == 8));
        assertTrue(StreamSupport.stream(ranges.spliterator(), false).anyMatch(r -> r.lower() == 2 && r.higher() == 5));
    }

    @Test
    void testRTT_InitialValue() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        // Initial RTT should be 333ms per RFC 9002
        assertEquals(333, space.getSmoothedRtt());
    }

    @Test
    void testRTT_MinRttTracking() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);

        long currentTime = 0;
        // Send multiple packets and ACK them with different delays
        for (int i = 0; i < 3; i++) {
            space.onPacketSent(currentTime, i, new RootPoolBuffer(ByteBuffer.allocate(10), mock(BufferPool.class), false).borrow(),  true);
            long delay = 10 + i * 10;
            currentTime += delay;

            List<PacketNumberSpace.AckRange> ackRanges = Arrays.asList(
                new PacketNumberSpace.AckRange(i, i)
            );
            space.onAckReceived(currentTime, i, ackRanges, 0, null, 0);
            java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = space.detectLostPackets(currentTime);
            assertTrue(lostPackets.isEmpty(), "No packets should be lost during RTT tracking");
        }

        // Min RTT should be the shortest sample (10ms)
        long minRtt = space.getMinRtt();
        assertEquals(10, minRtt, "Min RTT should be exactly 10ms");
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

        // Send non-ack-eliciting packet (e.g., ACK-only packet)
        space.onPacketSent(0, 0, new RootPoolBuffer(ByteBuffer.allocate(10), mock(BufferPool.class), false).borrow(), false);

        // ACK it
        List<PacketNumberSpace.AckRange> ackRanges = Arrays.asList(
            new PacketNumberSpace.AckRange(0, 0)
        );
        space.onAckReceived(0, 0, ackRanges, 0, null, 0);
        java.util.Map<Long, PacketNumberSpace.SentPacket> lostPackets = space.detectLostPackets(0);

        // RTT should still be initial value since packet wasn't ack-eliciting
        assertEquals(333, space.getSmoothedRtt());
        assertTrue(lostPackets.isEmpty(), "No packets should be lost");
    }

    @Test
    void testBytesAckedInLastRtt() {
        PacketNumberSpace space = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);
        space.setTimeWindowMs(100);
        PoolBuffer frames100 = new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow();
        frames100.buf().limit(100);
        PoolBuffer frames200 = new RootPoolBuffer(ByteBuffer.allocate(200), mock(BufferPool.class), false).borrow();
        frames200.buf().limit(200);

        long currentTime = 0;

        // 1. Establish RTT
        space.onPacketSent(currentTime, 0, frames100.borrow(), true);
        currentTime += 100;
        List<PacketNumberSpace.AckRange> range0 = Arrays.asList(new PacketNumberSpace.AckRange(0, 0));
        space.onAckReceived(currentTime, 0, range0, 0, null, 0);

        long rtt = space.getSmoothedRtt();
        // smoothedRtt will be ~100ms because it's the first sample.
        assertEquals(100, rtt, "RTT should be 100ms");

        // 2. Clear established RTT data from bytesAckedInLastRtt window
        currentTime += 200; // More than smoothedRtt and timeWindowMs
        space.detectLostPackets(currentTime);
        assertEquals(0, space.getWindowedStats().bytesAckedInLastRtt(), "Window should be clear");

        // 3. Send and ACK packets
        space.onPacketSent(currentTime, 1, frames100.borrow(), true);
        space.onPacketSent(currentTime, 2, frames200.borrow(), true);

        List<PacketNumberSpace.AckRange> range1_2 = Arrays.asList(new PacketNumberSpace.AckRange(1, 2));
        space.onAckReceived(currentTime, 2, range1_2, 0, null, 0);

        // Bytes acked should be 100 + 200 = 300
        long actual = space.getWindowedStats().bytesAckedInLastRtt();
        assertEquals(300, actual, "Expected 300 bytes, got: " + actual + " (RTT=" + rtt + ")");

        // 4. Wait for RTT to pass
        currentTime += 200;
        space.detectLostPackets(currentTime);

        // Bytes acked should now be 0 as the window passed
        assertEquals(0, space.getWindowedStats().bytesAckedInLastRtt(), "Should be 0 after RTT window passed");
    }
}
