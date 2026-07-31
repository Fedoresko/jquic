/*
 * Copyright 2026 Fedor Malyshev
 *
 * Licensed under the Apache License, Version 2.0 (the "License") ;
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
package org.jquic.quic.struct;

import org.jquic.quic.PacketNumberSpace;
import org.jquic.quic.QuicConnection;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.streamapi.CongestionControl;
import org.jquic.quic.streamapi.impl.ApplicationData;
import org.jquic.quic.streamapi.impl.FlightControl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

class AppDataPriorityQueueTest {

    private AppDataPriorityQueue queue;

    @Mock
    private QuicConnection connection;
    @Mock
    private CongestionControl congestionControl;
    @Mock
    private TriStateQueue<ApplicationData> triStateQueue;
    @Mock
    private FlightControl flightControl;
    @Mock
    private PacketNumberSpace applicationSpace;
    @Mock
    private PacketNumberSpace.WindowedStats windowedStats;
    @Mock
    private PoolBuffer poolBuffer;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        queue = new AppDataPriorityQueue();

        // Stubbing the complex chain in getCongestionDelayNanos
        when(connection.getCongestionControl()).thenReturn(congestionControl);
        when(connection.getApplicationSpace()).thenReturn(applicationSpace);
        when(applicationSpace.getWindowedStats()).thenReturn(windowedStats);
        
        // Default values for common congestion control inputs
        when(connection.getConnectionId()).thenReturn(12345L);
        when(applicationSpace.getSmoothedRtt()).thenReturn(100L);
        when(applicationSpace.getLatestRtt()).thenReturn(110L);
        when(applicationSpace.getMinRtt()).thenReturn(90L);
        when(applicationSpace.getLossTime()).thenReturn(0L);
        when(applicationSpace.getServerCeCounter()).thenReturn(0L);
        
        when(windowedStats.bytesAckedInLastRtt()).thenReturn(1000L);
        when(windowedStats.bytesLostInLastRtt()).thenReturn(0L);
        when(windowedStats.bytesAcked()).thenReturn(5000L);
        when(windowedStats.bytesLost()).thenReturn(0L);
        when(windowedStats.packetsAcked()).thenReturn(50L);
        when(windowedStats.intervalCePackets()).thenReturn(0L);

        when(flightControl.getTotalInFlightBytes()).thenReturn(500L);
        when(flightControl.getMaxStreamDataCap()).thenReturn(10000);
        when(flightControl.getBytesBuffered()).thenReturn(200L);

        ByteBuffer byteBuffer = ByteBuffer.allocate(100);
        when(poolBuffer.buf()).thenReturn(byteBuffer);
    }

    @Test
    void testAdd() {
        long currentTime = 1000000L; // 1ms in nanos
        long streamId = 1L;
        ApplicationData data = new ApplicationData(connection, flightControl, streamId, poolBuffer);
        
        when(triStateQueue.poll()).thenReturn(data);
        
        long delay = 500L;
        when(congestionControl.getDelay(anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong())).thenReturn(delay);

        queue.add(triStateQueue, currentTime);

        assertEquals(currentTime + delay, queue.nextTimestamp());
    }

    @Test
    void testPoll() {
        long currentTime = 1000000L;
        long streamId = 1L;
        ApplicationData data1 = new ApplicationData(connection, flightControl, streamId, poolBuffer);
        ApplicationData data2 = new ApplicationData(connection, flightControl, streamId, poolBuffer);
        
        // Initial add
        when(triStateQueue.poll()).thenReturn(data1);
        long delay1 = 500L;
        when(congestionControl.getDelay(eq(currentTime / 1_000_000), eq((long)100), eq(12345L), eq(streamId), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong())).thenReturn(delay1);
        
        queue.add(triStateQueue, currentTime);
        
        // When polling, it should return data1 and try to poll triStateQueue for next data
        when(triStateQueue.poll()).thenReturn(data2);
        long delay2 = 600L;
        // The poll method uses currentTimeNs passed to it for delay calculation of NEW data
        long pollTime = 2000000L;
        when(congestionControl.getDelay(eq(pollTime / 1_000_000), eq((long)100), eq(12345L), eq(streamId), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong())).thenReturn(delay2);

        ApplicationData polled = queue.poll(pollTime);

        assertEquals(data1, polled);
        // Verify that data2 was added back with new timestamp
        assertEquals(pollTime + delay2, queue.nextTimestamp());
    }

    @Test
    void testPollEmptyQueue() {
        assertNull(queue.poll(1000L));
    }

    @Test
    void testPollReturnsDataEvenIfNoMoreInTriState() {
        long currentTime = 1000000L;
        long streamId = 1L;
        ApplicationData data = new ApplicationData(connection, flightControl, streamId, poolBuffer);
        
        when(triStateQueue.poll()).thenReturn(data);
        queue.add(triStateQueue, currentTime);
        
        // No more data in triStateQueue
        when(triStateQueue.poll()).thenReturn(null);
        
        ApplicationData polled = queue.poll(2000000L);
        assertEquals(data, polled);
        
        // Queue should be empty now
        assertNull(queue.poll(3000000L));
    }

    @Test
    void testServiceDataHasNoDelay() {
        long currentTime = 1000000L;
        long streamId = -2L; // StreamManager.SERVICE_DATA is -2
        ApplicationData data = new ApplicationData(connection, flightControl, streamId, poolBuffer);
        
        when(triStateQueue.poll()).thenReturn(data);
        
        queue.add(triStateQueue, currentTime);
        
        // nextTimestamp should be exactly currentTime because delay is 0 for service data
        assertEquals(currentTime, queue.nextTimestamp());
        verify(congestionControl, never()).getDelay(anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong());
    }

    @Test
    void testInterleaving() {
        long currentTime = 1000000L;
        
        // Source 1: Delay 1000ns
        TriStateQueue<ApplicationData> source1 = mock(TriStateQueue.class);
        ApplicationData data1_1 = new ApplicationData(connection, flightControl, 1L, poolBuffer);
        when(source1.poll()).thenReturn(data1_1);
        when(congestionControl.getDelay(anyLong(), anyLong(), anyLong(), eq(1L), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong())).thenReturn(1000L);
        
        // Source 2: Delay 500ns
        TriStateQueue<ApplicationData> source2 = mock(TriStateQueue.class);
        ApplicationData data2_1 = new ApplicationData(connection, flightControl, 2L, poolBuffer);
        when(source2.poll()).thenReturn(data2_1);
        when(congestionControl.getDelay(anyLong(), anyLong(), anyLong(), eq(2L), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong())).thenReturn(500L);

        queue.add(source1, currentTime); // Next timestamp: currentTime + 1000
        queue.add(source2, currentTime); // Next timestamp: currentTime + 500
        
        assertEquals(currentTime + 500, queue.nextTimestamp());
        
        // Polling should return source 2 first
        when(source2.poll()).thenReturn(null); // No more data in source 2 after poll
        ApplicationData polled1 = queue.poll(currentTime + 500);
        assertEquals(data2_1, polled1);
        
        assertEquals(currentTime + 1000, queue.nextTimestamp());
        
        when(source1.poll()).thenReturn(null);
        ApplicationData polled2 = queue.poll(currentTime + 1000);
        assertEquals(data1_1, polled2);
    }

    @Test
    void testFairnessWithZeroDelay() {
        long currentTime = 1000000L;
        
        // Three sources with 0 delay (e.g. all service data or CC returns 0)
        TriStateQueue<ApplicationData> source1 = mock(TriStateQueue.class);
        ApplicationData data1 = new ApplicationData(connection, flightControl, -2L, poolBuffer);
        when(source1.poll()).thenReturn(data1);
        
        TriStateQueue<ApplicationData> source2 = mock(TriStateQueue.class);
        ApplicationData data2 = new ApplicationData(connection, flightControl, -2L, poolBuffer);
        when(source2.poll()).thenReturn(data2);
        
        TriStateQueue<ApplicationData> source3 = mock(TriStateQueue.class);
        ApplicationData data3 = new ApplicationData(connection, flightControl, -2L, poolBuffer);
        when(source3.poll()).thenReturn(data3);

        // Add them in order
        queue.add(source1, currentTime);
        queue.add(source2, currentTime);
        queue.add(source3, currentTime);
        
        // They all have the same timestamp (currentTime). 
        // TimeoutHeap should maintain FIFO order for elements with same timestamp if it's stable,
        // or at least we expect some fairness.
        
        // Ensure they are returned in the order they were added if delay is same
        when(source1.poll()).thenReturn(null);
        when(source2.poll()).thenReturn(null);
        when(source3.poll()).thenReturn(null);

        assertEquals(data1, queue.poll(currentTime));
        assertEquals(data2, queue.poll(currentTime));
        assertEquals(data3, queue.poll(currentTime));
    }

    @Test
    void testTriStateQueueWithMultipleRecords() {
        long currentTime = 1000000L;
        long streamId = 1L;
        
        TriStateQueue<ApplicationData> source = mock(TriStateQueue.class);
        ApplicationData data1 = new ApplicationData(connection, flightControl, streamId, poolBuffer);
        ApplicationData data2 = new ApplicationData(connection, flightControl, streamId, poolBuffer);
        ApplicationData data3 = new ApplicationData(connection, flightControl, streamId, poolBuffer);
        
        // First record returned on add()
        when(source.poll()).thenReturn(data1);
        when(congestionControl.getDelay(anyLong(), anyLong(), anyLong(), eq(streamId), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong())).thenReturn(100L);
        
        queue.add(source, currentTime);
        
        // Polling data1 should trigger poll for next data
        when(source.poll()).thenReturn(data2);
        ApplicationData polled1 = queue.poll(currentTime + 100);
        assertEquals(data1, polled1);
        assertEquals(currentTime + 100 + 100, queue.nextTimestamp());
        
        // Polling data2 should trigger poll for next data
        when(source.poll()).thenReturn(data3);
        ApplicationData polled2 = queue.poll(currentTime + 200);
        assertEquals(data2, polled2);
        assertEquals(currentTime + 200 + 100, queue.nextTimestamp());
        
        // Polling data3 should find no more data
        when(source.poll()).thenReturn(null);
        ApplicationData polled3 = queue.poll(currentTime + 300);
        assertEquals(data3, polled3);
        
        // Queue should be empty
        assertNull(queue.poll(currentTime + 400));
    }

    @Test
    void testFairnessInterleavingTwoQueues() {
        long currentTime = 1000000L;
        long delay = 100L;

        // Source 1 with 2 records
        TriStateQueue<ApplicationData> source1 = mock(TriStateQueue.class, "source1");
        ApplicationData data1_1 = new ApplicationData(connection, flightControl, 10L, poolBuffer);
        ApplicationData data1_2 = new ApplicationData(connection, flightControl, 10L, poolBuffer);
        
        // Source 2 with 2 records
        TriStateQueue<ApplicationData> source2 = mock(TriStateQueue.class, "source2");
        ApplicationData data2_1 = new ApplicationData(connection, flightControl, 20L, poolBuffer);
        ApplicationData data2_2 = new ApplicationData(connection, flightControl, 20L, poolBuffer);

        // Mock delay for both sources
        when(congestionControl.getDelay(anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong())).thenReturn(delay);

        // Setup sequences for source 1
        when(source1.poll()).thenReturn(data1_1).thenReturn(data1_2).thenReturn(null);
        
        // Setup sequences for source 2
        when(source2.poll()).thenReturn(data2_1).thenReturn(data2_2).thenReturn(null);

        // Add both sources at the same time
        // Since they have the same delay and same current time, they should have same target timestamp
        queue.add(source1, currentTime);
        queue.add(source2, currentTime);

        // Expectations:
        // 1. First poll returns data1_1 (added first). Re-enqueues source1 with (pollTime + delay).
        // 2. Second poll returns data2_1 (has earlier timestamp than source1's next). Re-enqueues source2 with (pollTime + delay).
        // 3. Third poll returns data1_2.
        // 4. Fourth poll returns data2_2.

        // Poll 1
        long pollTime1 = currentTime + delay;
        assertEquals(data1_1, queue.poll(pollTime1));
        
        // Poll 2
        long pollTime2 = currentTime + delay; // Still at the same "logical" time or slightly after
        assertEquals(data2_1, queue.poll(pollTime2));

        // Poll 3
        long pollTime3 = pollTime1 + delay;
        assertEquals(data1_2, queue.poll(pollTime3));

        // Poll 4
        long pollTime4 = pollTime2 + delay;
        assertEquals(data2_2, queue.poll(pollTime4));

        assertNull(queue.poll(pollTime4 + delay));
    }

    @Test
    void testIdenticalPollTimes() {
        long currentTime = 1000000L;
        long delay = 0L; // Force identical poll times

        // Create 2 sources with 3 records each
        TriStateQueue<ApplicationData> source1 = mock(TriStateQueue.class, "source1");
        ApplicationData d1_1 = new ApplicationData(connection, flightControl, 101L, poolBuffer);
        ApplicationData d1_2 = new ApplicationData(connection, flightControl, 102L, poolBuffer);
        ApplicationData d1_3 = new ApplicationData(connection, flightControl, 103L, poolBuffer);
        when(source1.poll()).thenReturn(d1_1).thenReturn(d1_2).thenReturn(d1_3).thenReturn(null);

        TriStateQueue<ApplicationData> source2 = mock(TriStateQueue.class, "source2");
        ApplicationData d2_1 = new ApplicationData(connection, flightControl, 201L, poolBuffer);
        ApplicationData d2_2 = new ApplicationData(connection, flightControl, 202L, poolBuffer);
        ApplicationData d2_3 = new ApplicationData(connection, flightControl, 203L, poolBuffer);
        when(source2.poll()).thenReturn(d2_1).thenReturn(d2_2).thenReturn(d2_3).thenReturn(null);

        // CC returns 0 delay
        when(congestionControl.getDelay(anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong())).thenReturn(delay);

        // Add them at the same time
        queue.add(source1, currentTime);
        queue.add(source2, currentTime);

        // Verify interleaving: source1 - source2 - source1 - source2 - source1 - source2
        assertEquals(d1_1, queue.poll(currentTime));
        assertEquals(d2_1, queue.poll(currentTime));
        assertEquals(d1_2, queue.poll(currentTime));
        assertEquals(d2_2, queue.poll(currentTime));
        assertEquals(d1_3, queue.poll(currentTime));
        assertEquals(d2_3, queue.poll(currentTime));

        assertNull(queue.poll(currentTime));
    }
}
