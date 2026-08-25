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
import org.jquic.quic.buffers.TestPoolBuffer;
import org.jquic.quic.packets.PacketNumberSpace;
import org.jquic.quic.packets.PacketPhase;
import org.jquic.quic.paths.ConnectionPathController;
import org.jquic.quic.streamapi.CongestionControl;
import org.jquic.quic.struct.SortedIntervals;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * Tests for PacketNumberSpace - packet number management, ACK processing, loss detection.
 */
class PacketNumberSpaceTest {
    private static final InetSocketAddress TEST_ADDRESS = new InetSocketAddress("127.0.0.1", 8080);

    @Test
    void testAllocatePacketNumber_Sequential() {
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.INITIAL);

        assertEquals(0, space.allocatePacketNumber());
        assertEquals(1, space.allocatePacketNumber());
        assertEquals(2, space.allocatePacketNumber());
        assertEquals(3, space.allocatePacketNumber());
    }

    @Test
    void testOnPacketReceived_TracksLargest() {
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.INITIAL);

        space.onPacketReceived(System.currentTimeMillis(), 5, 0);
        assertEquals(5, space.getLargestReceivedPacketNumber());

        space.onPacketReceived(System.currentTimeMillis(), 3, 0);
        assertEquals(5, space.getLargestReceivedPacketNumber());

        space.onPacketReceived(System.currentTimeMillis(), 10, 0);
        assertEquals(10, space.getLargestReceivedPacketNumber());
    }

    @Test
    void testOnPacketSent_TracksPackets() {
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.INITIAL);
        PoolBuffer frames = new TestPoolBuffer(ByteBuffer.allocate(10));

        space.onPacketSent(0, 0, frames,  true, TEST_ADDRESS);
        space.onPacketSent(0, 1, frames,  true, TEST_ADDRESS);

        assertEquals(2, space.getUnackedPacketCount());
        assertTrue(space.hasUnackedPackets());
    }

    @Test
    void testOnAckReceived_RemovesAckedPackets() {
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.INITIAL);

        // Send packets 0, 1, 2
        space.onPacketSent(0, 0, new TestPoolBuffer(ByteBuffer.allocate(10)).borrow(),  true, TEST_ADDRESS);
        space.onPacketSent(0, 1, new TestPoolBuffer(ByteBuffer.allocate(10)).borrow(),  true, TEST_ADDRESS);
        space.onPacketSent(0, 2, new TestPoolBuffer(ByteBuffer.allocate(10)).borrow(),  true, TEST_ADDRESS);

        assertEquals(3, space.getUnackedPacketCount());

        // ACK packets 0 and 1
        List<PacketNumberSpace.AckRange> ackRanges = List.of(
                new PacketNumberSpace.AckRange(0, 1)
        );
        space.onAckReceived(0, 1, ackRanges, 0, null, 0, TEST_ADDRESS);
        Deque<Long> lostPackets = new ArrayDeque<>();
        space.detectLostPackets(0, a->lostPackets.offer(a.getPacketNumber()));

        // Only packet 2 should remain
        assertEquals(1, space.getUnackedPacketCount());
        assertTrue(lostPackets.isEmpty(), "No packets should be lost yet");
    }

    @Test
    void testOnAckReceived_UpdatesRTT() {
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.INITIAL);
        ConnectionPathController connectionPathController = new ConnectionPathController(mock(QuicConnection.class), TEST_ADDRESS);
        space.setConnectionPathController(connectionPathController);

        // Send packet 0 at T=0
        space.onPacketSent(0, 0, new TestPoolBuffer(ByteBuffer.allocate(10)).borrow(),  true, TEST_ADDRESS);

        // ACK packet 0 at T=50
        List<PacketNumberSpace.AckRange> ackRanges = List.of(
            new PacketNumberSpace.AckRange(0, 0)
        );
        space.onAckReceived(50, 0, ackRanges, 0, null, 0, TEST_ADDRESS);
        Deque<Long> lostPackets = new ArrayDeque<>();
        space.detectLostPackets(50, a->lostPackets.offer(a.getPacketNumber()));

        // RTT should be updated
        long rtt = space.getWindowedStatCounter(TEST_ADDRESS).getLatestRtt();
        assertEquals(50, rtt, "RTT should be exactly 50ms, got: " + rtt);
        assertTrue(lostPackets.isEmpty(), "No packets should be lost");
    }

    @Test
    void testDetectLostPackets_PacketThreshold() {
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.INITIAL);
        space.setConnectionPathController(new ConnectionPathController(mock(QuicConnection.class), TEST_ADDRESS));

        // Send packets 0-10 at T=0
        for (int i = 0; i <= 10; i++) {
            space.onPacketSent(0, i, new TestPoolBuffer(ByteBuffer.allocate(10)).borrow(),  true, TEST_ADDRESS);
        }

        // ACK packet 10 at T=10 (leaving 0-9 unacked)
        List<PacketNumberSpace.AckRange> ackRanges = List.of(
            new PacketNumberSpace.AckRange(10, 10)
        );
        space.onAckReceived(10, 10, ackRanges, 0, null, 0, TEST_ADDRESS);
        Deque<Long> lostPackets = new ArrayDeque<>();
        space.detectLostPackets(10, a->lostPackets.offer(a.getPacketNumber()));

        // Packets 0-6 should be declared lost (more than 3 below largest acked)
        assertTrue(lostPackets.contains(0L), "Packet 0 should be lost");
        assertTrue(lostPackets.contains(6L), "Packet 6 should be lost");
        assertFalse(lostPackets.contains(7L), "Packet 7 should not be lost (within threshold)");
        assertFalse(lostPackets.contains(8L), "Packet 8 should not be lost");
        assertFalse(lostPackets.contains(9L), "Packet 9 should not be lost");
    }

    @Test
    void testDetectLostPackets_TimeThreshold() {
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.INITIAL);
        space.setConnectionPathController(new ConnectionPathController(mock(QuicConnection.class), TEST_ADDRESS));

        // Send packet 0 at T=0
        space.onPacketSent(0, 0, new TestPoolBuffer(ByteBuffer.allocate(10)).borrow(),  true, TEST_ADDRESS);

        // Send and ACK packet 1 at T=100 to establish RTT=100
        space.onPacketSent(100, 1, new TestPoolBuffer(ByteBuffer.allocate(10)).borrow(),  true, TEST_ADDRESS);
        List<PacketNumberSpace.AckRange> ackRanges1 = List.of(
            new PacketNumberSpace.AckRange(1, 1)
        );
        space.onAckReceived(200, 1, ackRanges1, 0, null, 0, TEST_ADDRESS);

        // Send and ACK packet 2 at T=300 to trigger loss detection for packet 0
        space.onPacketSent(300, 2, new TestPoolBuffer(ByteBuffer.allocate(10)).borrow(),  true, TEST_ADDRESS);
        List<PacketNumberSpace.AckRange> ackRanges2 = List.of(
            new PacketNumberSpace.AckRange(2, 2)
        );
        space.onAckReceived(400, 2, ackRanges2, 0, null, 0, TEST_ADDRESS);
        
        // Wait for loss delay threshold (9/8 * RTT)
        // RTT is ~100ms. Loss delay is 125ms.
        // Packet 0 sent at 0. Deadline was ~125. At T=400 it should be lost.
        Deque<Long> lostPackets = new ArrayDeque<>();
        space.detectLostPackets(400, a->lostPackets.offer(a.getPacketNumber()));

        // Packet 0 should be lost due to time threshold
        assertTrue(lostPackets.contains(0L), "Packet 0 should be lost due to time threshold");
    }

    @Test
    void testGetAckRanges_SingleRange() {
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.INITIAL);

        // Receive contiguous packets 0-4
        for (long i = 0; i <= 4; i++) {
            space.onPacketReceived(System.currentTimeMillis(), i, 0);
        }

        SortedIntervals ranges = space.getAckRanges();

        SortedIntervals.Interval first = ranges.iterator().next();

        assertEquals(1, ranges.size());
        assertEquals(0, first.lower());
        assertEquals(4, first.higher());
    }

    @Test
    void testGetAckRanges_MultipleRanges() {
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.INITIAL);

        // Receive packets with gaps: 0-2, 5-7, 10
        space.onPacketReceived(System.currentTimeMillis(), 0, 0);
        space.onPacketReceived(System.currentTimeMillis(), 1, 0);
        space.onPacketReceived(System.currentTimeMillis(), 2, 0);
        space.onPacketReceived(System.currentTimeMillis(), 5, 0);
        space.onPacketReceived(System.currentTimeMillis(), 6, 0);
        space.onPacketReceived(System.currentTimeMillis(), 7, 0);
        space.onPacketReceived(System.currentTimeMillis(), 10, 0);

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
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.INITIAL);

        // Receive packets out of order
        space.onPacketReceived(System.currentTimeMillis(), 5, 0);
        space.onPacketReceived(System.currentTimeMillis(), 2, 0);
        space.onPacketReceived(System.currentTimeMillis(), 8, 0);
        space.onPacketReceived(System.currentTimeMillis(), 3, 0);
        space.onPacketReceived(System.currentTimeMillis(), 4, 0);

        SortedIntervals ranges = space.getAckRanges();


        // Should merge into ranges: [8], [2-5]
        assertEquals(2, ranges.size());
        assertTrue(StreamSupport.stream(ranges.spliterator(), false).anyMatch(r -> r.lower() == 8 && r.higher() == 8));
        assertTrue(StreamSupport.stream(ranges.spliterator(), false).anyMatch(r -> r.lower() == 2 && r.higher() == 5));
    }

    @Test
    void testRTT_InitialValue() {
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.INITIAL);
        ConnectionPathController connectionPathController = new ConnectionPathController(mock(QuicConnection.class), TEST_ADDRESS);
        space.setConnectionPathController(connectionPathController);

        // Initial RTT should be 333ms per RFC 9002
        assertEquals(333, space.getWindowedStatCounter(TEST_ADDRESS).getSmoothedRtt());
    }

    @Test
    void testRTT_MinRttTracking() {
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.INITIAL);
        ConnectionPathController connectionPathController = new ConnectionPathController(mock(QuicConnection.class), TEST_ADDRESS);
        space.setConnectionPathController(connectionPathController);


        long currentTime = 0;
        // Send multiple packets and ACK them with different delays
        for (int i = 0; i < 3; i++) {
            space.onPacketSent(currentTime, i, new TestPoolBuffer(ByteBuffer.allocate(10)).borrow(),  true, TEST_ADDRESS);
            long delay = 10 + i * 10;
            currentTime += delay;

            List<PacketNumberSpace.AckRange> ackRanges = List.of(
                new PacketNumberSpace.AckRange(i, i)
            );
            space.onAckReceived(currentTime, i, ackRanges, 0, null, 0, TEST_ADDRESS);
            Deque<Long> lostPackets = new ArrayDeque<>();
            space.detectLostPackets(currentTime, a->lostPackets.offer(a.getPacketNumber()));
            assertTrue(lostPackets.isEmpty(), "No packets should be lost during RTT tracking");
        }

        // Min RTT should be the shortest sample (10ms)
        long minRtt = space.getWindowedStatCounter(TEST_ADDRESS).getMinRtt();
        assertEquals(10, minRtt, "Min RTT should be exactly 10ms");
    }

    @Test
    void testHasUnackedPackets_Empty() {
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.INITIAL);

        assertFalse(space.hasUnackedPackets());
        assertEquals(0, space.getUnackedPacketCount());
    }

    @Test
    void testAckEliciting_NonAckElicitingPackets() {
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.INITIAL);
        ConnectionPathController connectionPathController = new ConnectionPathController(mock(QuicConnection.class), TEST_ADDRESS);
        space.setConnectionPathController(connectionPathController);

        // Send non-ack-eliciting packet (e.g., ACK-only packet)
        space.onPacketSent(0, 0, new TestPoolBuffer(ByteBuffer.allocate(10)).borrow(), false, TEST_ADDRESS);

        // ACK it
        List<PacketNumberSpace.AckRange> ackRanges = List.of(
            new PacketNumberSpace.AckRange(0, 0)
        );
        space.onAckReceived(0, 0, ackRanges, 0, null, 0, TEST_ADDRESS);
        Deque<Long> lostPackets = new ArrayDeque<>();
        space.detectLostPackets(0, a->lostPackets.offer(a.getPacketNumber()));

        // RTT should still be initial value since packet wasn't ack-eliciting
        assertEquals(333, space.getWindowedStatCounter(TEST_ADDRESS).getSmoothedRtt());
        assertTrue(lostPackets.isEmpty(), "No packets should be lost");
    }

    @Test
    void testGetAckDelay() {
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.APPLICATION);

        // No packets received yet
        assertEquals(0, space.getAckDelay(1000));

        // Receive packet at T=1000
        space.onPacketReceived(1000, 5, 0);

        // Delay at T=1008 should be (1008-1000)*1000 / 8 = 1000
        assertEquals(1000, space.getAckDelay(1008));

        // Receive larger packet at T=2000
        space.onPacketReceived(2000, 10, 0);

        // Delay at T=2008 should be (2008-2000)*1000 / 8 = 1000
        assertEquals(1000, space.getAckDelay(2008));

        // Receive smaller packet at T=3000 (should not update largest timestamp)
        space.onPacketReceived(3000, 7, 0);

        // Delay at T=3008 should still be relative to T=2000: (3008-2000)*1000 / 8 = 1008 * 125 = 126000
        assertEquals(126000, space.getAckDelay(3008));
    }

    @Test
    void testBytesAckedInLastRtt() {
        ConnectionPathController connectionPathController1 = new ConnectionPathController(mock(QuicConnection.class), TEST_ADDRESS);
        PacketNumberSpace space = new PacketNumberSpace(PacketPhase.INITIAL);
        space.setConnectionPathController(connectionPathController1);
        connectionPathController1.setCongestionControl(new CongestionControl() {
            public long getDelay(long currentTimeNanos, long currentTimeMs, long dataSize, long connectionId, long smoothedRtt, long lastRtt, long minRtt, long bytesAckedInRtt, long bytesLostInRtt, long bytesAckedInWindow, long bytesLostInWindow, long packetsAckedInWindow, long lastLostTimeMs, long lastAckedTimeMs, long inFlightData, long receiveBufferRemaining, long sendBufferSize, long ceCounter, long cePacketsInWindow) {
                return 0;
            }
            public int timeWindowMs() {
                return 100;
            }
        });
        PoolBuffer frames100 = new TestPoolBuffer(ByteBuffer.allocate(100)).borrow();
        frames100.buf().limit(100);
        PoolBuffer frames200 = new TestPoolBuffer(ByteBuffer.allocate(200)).borrow();
        frames200.buf().limit(200);

        long currentTime = 0;

        // 1. Establish RTT
        space.onPacketSent(currentTime, 0, frames100.borrow(), true, TEST_ADDRESS);
        currentTime += 100;
        List<PacketNumberSpace.AckRange> range0 = List.of(new PacketNumberSpace.AckRange(0, 0));
        space.onAckReceived(currentTime, 0, range0, 0, null, 0, TEST_ADDRESS);

        long rtt = space.getWindowedStatCounter(TEST_ADDRESS).getSmoothedRtt();
        // smoothedRtt will be ~100ms because it's the first sample.
        assertEquals(100, rtt, "RTT should be 100ms");

        // 2. Clear established RTT data from bytesAckedInLastRtt window
        currentTime += 200; // More than smoothedRtt and timeWindowMs
        space.detectLostPackets(currentTime, _->true);
        assertEquals(0, space.getWindowedStatCounter(TEST_ADDRESS).getBytesAckedInLastRtt(), "Window should be clear");

        // 3. Send and ACK packets
        space.onPacketSent(currentTime, 1, frames100.borrow(), true, TEST_ADDRESS);
        space.onPacketSent(currentTime, 2, frames200.borrow(), true, TEST_ADDRESS);

        List<PacketNumberSpace.AckRange> range1_2 = List.of(new PacketNumberSpace.AckRange(1, 2));
        space.onAckReceived(currentTime, 2, range1_2, 0, null, 0, TEST_ADDRESS);

        // Bytes acked should be 100 + 200 = 300
        long actual = space.getWindowedStatCounter(TEST_ADDRESS).getBytesAckedInLastRtt();
        assertEquals(300, actual, "Expected 300 bytes, got: " + actual + " (RTT=" + rtt + ")");

        // 4. Wait for RTT to pass
        currentTime += 200;
        space.detectLostPackets(currentTime, _->true);

        // Bytes acked should now be 0 as the window passed
        assertEquals(0, space.getWindowedStatCounter(TEST_ADDRESS).getBytesAckedInLastRtt(), "Should be 0 after RTT window passed");
    }
}

