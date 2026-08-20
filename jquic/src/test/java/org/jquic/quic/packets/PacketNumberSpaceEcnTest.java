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

import org.jquic.quic.QuicConnection;
import org.jquic.quic.QuicFrameBuilder;
import org.jquic.quic.QuicVarint;
import org.jquic.quic.buffers.BufferPool;
import org.jquic.quic.buffers.RootPoolBuffer;
import org.jquic.quic.paths.ConnectionPathController;
import org.jquic.quic.streamapi.CongestionControl;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class PacketNumberSpaceEcnTest {
    private static final InetSocketAddress TEST_ADDRESS = new InetSocketAddress("127.0.0.1", 4433);

    @Test
    void testEcnCounters() {
        PacketNumberSpace pns = new PacketNumberSpace(PacketPhase.APPLICATION);

        // ECN flags: 1 = CE, 2 = ECT(1), 4 = ECT(0) (based on code)
        // bit 0: isCe = (ecnFlags & 1) != 0
        // bit 1: isEct1 = (ecnFlags & 2) != 0
        // bit 2: isEct0 = (ecnFlags & 4) != 0

        pns.onPacketReceived(System.currentTimeMillis(), 1, 1); // CE
        pns.onPacketReceived(System.currentTimeMillis(), 2, 2); // ECT(1)
        pns.onPacketReceived(System.currentTimeMillis(), 3, 4); // ECT(0)
        pns.onPacketReceived(System.currentTimeMillis(), 4, 1); // CE again
        
        assertEquals(2, pns.clientEctCeCounter);
        assertEquals(1, pns.clientEct1Counter);
        assertEquals(1, pns.clientEct0Counter);
    }

    private static @NonNull ConnectionPathController getConnectionPathController() {
        ConnectionPathController connectionPathController = new ConnectionPathController(mock(QuicConnection.class), TEST_ADDRESS);
        connectionPathController.setCongestionControl(new CongestionControl() {
            @Override
            public long getDelay(long currentTimeMs, long dataSize, long connectionId, long smoothedRtt, long lastRtt, long minRtt, long bytesAckedInRtt, long bytesLostInRtt, long bytesAckedInWindow, long bytesLostInWindow, long packetsAckedInWindow, long lastLostTimeMs, long inFlightData, long receiveBufferRemaining, long sendBufferSize, long ceCounter, long cePacketsInWindow) {
                return 0;
            }
            @Override
            public int timeWindowMs() {
                return 100;
            }
        });
        return connectionPathController;
    }

    @Test
    void testIntervalCePacketsThisWindow() {
        PacketNumberSpace pns = new PacketNumberSpace(PacketPhase.APPLICATION);
        pns.setConnectionPathController(getConnectionPathController());

        pns.onAckReceived(0, 0, List.of(), 0, null, 0, TEST_ADDRESS); // Init
        pns.onAckReceived(0, 0, List.of(), 0, null, 2, TEST_ADDRESS); // CE increased by 2
        assertEquals(2, pns.getWindowedStatCounter(TEST_ADDRESS).getIntervalCePackets());
    }
    
    @Test
    void testAckReceivedWindowCalculations() {
        PacketNumberSpace pns = new PacketNumberSpace(PacketPhase.APPLICATION);
        pns.setConnectionPathController(getConnectionPathController());

        pns.onPacketSent(0, 1, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true, TEST_ADDRESS);
        pns.onPacketSent(0, 2, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true, TEST_ADDRESS);
        
        pns.onAckReceived(0, 2, List.of(new PacketNumberSpace.AckRange(1, 2)), 0, null, 0, TEST_ADDRESS);
        
        assertEquals(2, pns.getWindowedStatCounter(TEST_ADDRESS).getPacketsAcked());
        assertEquals(200, pns.getWindowedStatCounter(TEST_ADDRESS).getBytesAcked());
    }

    @Test
    void testLostPacketsWindowCalculations() {
        PacketNumberSpace pns = new PacketNumberSpace(PacketPhase.APPLICATION);
        pns.setConnectionPathController(getConnectionPathController());

        pns.onPacketSent(0, 1, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true, TEST_ADDRESS);
        pns.onPacketSent(0, 2, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true, TEST_ADDRESS);
        pns.onPacketSent(0, 3, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true, TEST_ADDRESS);
        pns.onPacketSent(0, 4, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true, TEST_ADDRESS);
        pns.onPacketSent(0, 5, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true, TEST_ADDRESS);

        // Ack packet 5 to set largestAckedPacketNumber
        pns.onAckReceived(0, 5, List.of(new PacketNumberSpace.AckRange(5, 5)), 0, null, 0, TEST_ADDRESS);
        
        // Packet threshold is 3. Packet 1 should be declared lost (5 - 1 = 4 > 3)
        pns.detectLostPackets(0);
        
        assertEquals(100, pns.getWindowedStatCounter(TEST_ADDRESS).getBytesLost());
    }

    @Test
    void testCombinedWindowedStats() {
        PacketNumberSpace pns = new PacketNumberSpace(PacketPhase.APPLICATION);
        pns.setConnectionPathController(getConnectionPathController());

        pns.onPacketSent(0, 1, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true, TEST_ADDRESS);
        pns.onPacketSent(0, 2, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true, TEST_ADDRESS);
        pns.onPacketSent(0, 3, new RootPoolBuffer(ByteBuffer.allocate(100), mock(BufferPool.class), false).borrow(), true, TEST_ADDRESS);

        // Receive packet (ECN flags 0)
        pns.onPacketReceived(System.currentTimeMillis(), 10, 0);

        // Init CE counter
        pns.onAckReceived(0, 0, List.of(), 0, null, 0, TEST_ADDRESS);

        // Ack packets 1 and 2, and report 1 CE
        pns.onAckReceived(0, 2, List.of(new PacketNumberSpace.AckRange(1, 2)), 0, null, 1, TEST_ADDRESS);

        // Lose packet 3
        pns.onAckReceived(0, 7, List.of(new PacketNumberSpace.AckRange(7, 7)), 0, null, 1, TEST_ADDRESS);
        pns.detectLostPackets(0);

        assertEquals(1, pns.getWindowedStatCounter(TEST_ADDRESS).getIntervalCePackets());
        assertEquals(200, pns.getWindowedStatCounter(TEST_ADDRESS).getBytesAcked());
        assertEquals(2, pns.getWindowedStatCounter(TEST_ADDRESS).getPacketsAcked());
        assertEquals(100, pns.getWindowedStatCounter(TEST_ADDRESS).getBytesLost());
    }

    @Test
    void testWriteAckEcnFrame() {
        PacketNumberSpace pns = new PacketNumberSpace(PacketPhase.APPLICATION);

        long timestamp = 1000;
        pns.onPacketReceived(timestamp, 10, 1); // CE packet
        pns.clientEct0Counter = 5;
        pns.clientEct1Counter = 7;
        pns.clientEctCeCounter = 2;

        ByteBuffer buffer = ByteBuffer.allocate(128);
        QuicFrameBuilder.writeAckEcnFrame(pns, timestamp + 1, buffer);

        // buffer is flipped by writeAckEcnFrame
        assertEquals(0x03, buffer.get()); // Type
        Assertions.assertEquals(10, QuicVarint.read(buffer)); // Largest Acked
        // (timestamp+1 - timestamp) * 1000 / 8 = 1 * 1000 / 8 = 125
        assertEquals(125, QuicVarint.read(buffer)); // Ack Delay
        assertEquals(0, QuicVarint.read(buffer)); // Range Count
        assertEquals(0, QuicVarint.read(buffer)); // First Range Length

        assertEquals(5, QuicVarint.read(buffer)); // ECT(0)
        assertEquals(7, QuicVarint.read(buffer)); // ECT(1)
        assertEquals(2, QuicVarint.read(buffer)); // CE
    }
}

