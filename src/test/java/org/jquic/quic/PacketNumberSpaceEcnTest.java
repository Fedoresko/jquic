package org.jquic.quic;

import org.jquic.quic.buffers.BufferPool;
import org.jquic.quic.buffers.RootPoolBuffer;
import org.junit.jupiter.api.Test;
import java.nio.ByteBuffer;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class PacketNumberSpaceEcnTest {

    @Test
    void testEcnCounters() {
        PacketNumberSpace pns = new PacketNumberSpace(PacketNumberSpace.PacketPhase.APPLICATION);
        pns.setTimeWindowMs(100);
        
        // ECN flags: 1 = CE, 2 = ECT(1), 4 = ECT(0) (based on code)
        // bit 0: isCe = (ecnFlags & 1) != 0
        // bit 1: isEct1 = (ecnFlags & 2) != 0
        // bit 2: isEct0 = (ecnFlags & 4) != 0

        pns.onPacketReceived(1, 1); // CE
        pns.onPacketReceived(2, 2); // ECT(1)
        pns.onPacketReceived(3, 4); // ECT(0)
        pns.onPacketReceived(4, 1); // CE again
        
        assertEquals(2, pns.clientEctCeCounter);
        assertEquals(1, pns.clientEct1Counter);
        assertEquals(1, pns.clientEct0Counter);
    }

    @Test
    void testIntervalCePacketsThisWindow() throws InterruptedException {
        int windowMs = 100; // 100ms
        PacketNumberSpace pns = new PacketNumberSpace(PacketNumberSpace.PacketPhase.APPLICATION);
        pns.setTimeWindowMs(windowMs);

        pns.onAckReceived(0, 0, List.of(), 0, null, 0); // Init
        pns.onAckReceived(0, 0, List.of(), 0, null, 2); // CE increased by 2
        assertEquals(2, pns.getWindowedStats().intervalCePackets());
    }
    
    @Test
    void testAckReceivedWindowCalculations() {
        int windowMs = 100; // 100ms
        PacketNumberSpace pns = new PacketNumberSpace(PacketNumberSpace.PacketPhase.APPLICATION);
        pns.setTimeWindowMs(windowMs);

        pns.onPacketSent(0, 1, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true);
        pns.onPacketSent(0, 2, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true);
        
        pns.onAckReceived(0, 2, List.of(new PacketNumberSpace.AckRange(1, 2)), 0, null, 0);
        
        PacketNumberSpace.WindowedStats stats = pns.getWindowedStats();
        assertEquals(2, stats.packetsAcked());
        assertEquals(200, stats.bytesAcked());
    }

    @Test
    void testLostPacketsWindowCalculations() {
        int windowMs = 100; // 100ms
        PacketNumberSpace pns = new PacketNumberSpace(PacketNumberSpace.PacketPhase.APPLICATION);
        pns.setTimeWindowMs(windowMs);

        pns.onPacketSent(0, 1, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true);
        pns.onPacketSent(0, 2, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true);
        pns.onPacketSent(0, 3, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true);
        pns.onPacketSent(0, 4, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true);
        pns.onPacketSent(0, 5, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true);

        // Ack packet 5 to set largestAckedPacketNumber
        pns.onAckReceived(0, 5, List.of(new PacketNumberSpace.AckRange(5, 5)), 0, null, 0);
        
        // Packet threshold is 3. Packet 1 should be declared lost (5 - 1 = 4 > 3)
        pns.detectLostPackets(0);
        
        assertEquals(100, pns.getWindowedStats().bytesLost());
    }

    @Test
    void testCombinedWindowedStats() {
        int windowMs = 100; // 100ms
        PacketNumberSpace pns = new PacketNumberSpace(PacketNumberSpace.PacketPhase.APPLICATION);
        pns.setTimeWindowMs(windowMs);

        pns.onPacketSent(0, 1, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true);
        pns.onPacketSent(0, 2, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true);
        pns.onPacketSent(0, 3, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true);

        // Receive packet (ECN flags 0)
        pns.onPacketReceived(10, 0);

        // Init CE counter
        pns.onAckReceived(0, 0, List.of(), 0, null, 0);

        // Ack packets 1 and 2, and report 1 CE
        pns.onAckReceived(0, 2, List.of(new PacketNumberSpace.AckRange(1, 2)), 0, null, 1);

        // Lose packet 3
        pns.onAckReceived(0, 7, List.of(new PacketNumberSpace.AckRange(7, 7)), 0, null, 1);
        pns.detectLostPackets(0);

        PacketNumberSpace.WindowedStats stats = pns.getWindowedStats();

        assertEquals(1, stats.intervalCePackets());
        assertEquals(200, stats.bytesAcked());
        assertEquals(2, stats.packetsAcked());
        assertEquals(100, stats.bytesLost());
    }

    @Test
    void testWriteAckEcnFrame() {
        PacketNumberSpace pns = new PacketNumberSpace(PacketNumberSpace.PacketPhase.APPLICATION);
        pns.setTimeWindowMs(100);

        pns.onPacketReceived(10, 1); // CE packet
        pns.clientEct0Counter = 5;
        pns.clientEct1Counter = 7;
        pns.clientEctCeCounter = 2;

        ByteBuffer buffer = ByteBuffer.allocate(128);
        QuicFrameBuilder.writeAckEcnFrame(pns, buffer);

        // buffer is flipped by writeAckEcnFrame
        assertEquals(0x03, buffer.get()); // Type
        assertEquals(10, QuicVarint.read(buffer)); // Largest Acked
        assertEquals(0, QuicVarint.read(buffer)); // Ack Delay
        assertEquals(0, QuicVarint.read(buffer)); // Range Count
        assertEquals(0, QuicVarint.read(buffer)); // First Range Length

        assertEquals(5, QuicVarint.read(buffer)); // ECT(0)
        assertEquals(7, QuicVarint.read(buffer)); // ECT(1)
        assertEquals(2, QuicVarint.read(buffer)); // CE
    }
}
