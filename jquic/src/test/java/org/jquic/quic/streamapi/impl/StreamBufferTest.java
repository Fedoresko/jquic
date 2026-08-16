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
package org.jquic.quic.streamapi.impl;

import org.jquic.quic.QuicException;
import org.jquic.quic.buffers.PoolBuffer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class StreamBufferTest {
    private StreamBuffer streamBuffer;
    private static final long STREAM_ID = 4;
    private static final int CAPACITY = 1000;

    @BeforeEach
    void setUp() {
        streamBuffer = new StreamBuffer(STREAM_ID, CAPACITY);
    }

    private PoolBuffer mockPoolBuffer(byte[] data) {
        PoolBuffer poolBuffer = mock(PoolBuffer.class);
        ByteBuffer byteBuffer = ByteBuffer.wrap(data);
        when(poolBuffer.buf()).thenReturn(byteBuffer);
        when(poolBuffer.borrow()).thenAnswer(_ -> {
            PoolBuffer borrowed = mock(PoolBuffer.class);
            ByteBuffer dup = byteBuffer.duplicate();
            when(borrowed.buf()).thenReturn(dup);
            // Recursively handle borrow on borrowed
            when(borrowed.borrow()).thenAnswer(_ -> {
                PoolBuffer borrowed2 = mock(PoolBuffer.class);
                ByteBuffer dup2 = dup.duplicate();
                when(borrowed2.buf()).thenReturn(dup2);
                return borrowed2;
            });
            return borrowed;
        });
        return poolBuffer;
    }

    @Test
    void testAddInOrderData() throws Exception {
        byte[] data1 = "Hello ".getBytes();
        PoolBuffer pb1 = mockPoolBuffer(data1);

        assertTrue(streamBuffer.addIncomingData(0, pb1, false), "Should return true for in-order data");
        assertEquals(data1.length, streamBuffer.getBufferedBytes());

        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        assertArrayEquals(data1, read.getData());
        assertFalse(read.isLast());
        assertEquals(0, streamBuffer.getBufferedBytes());
    }

    @Test
    void testAddOutOfOrderData() throws Exception {
        byte[] data1 = "Hello ".getBytes();
        byte[] data2 = "World".getBytes();
        PoolBuffer pb1 = mockPoolBuffer(data1);
        PoolBuffer pb2 = mockPoolBuffer(data2);

        // Add second part first
        assertFalse(streamBuffer.addIncomingData(data1.length, pb2, false), "Should return false as there is a gap");
        assertEquals(data2.length, streamBuffer.getBufferedBytes());
        assertNull(streamBuffer.readAvailableData(), "Should not be able to read due to gap");

        // Add first part
        assertTrue(streamBuffer.addIncomingData(0, pb1, false), "Should return true now as gap is filled");
        assertEquals(data1.length + data2.length, streamBuffer.getBufferedBytes());

        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        assertArrayEquals("Hello World".getBytes(), read.getData());
        assertFalse(read.isLast());
        assertEquals(0, streamBuffer.getBufferedBytes());
    }

    @Test
    void testDuplicateData() throws Exception {
        byte[] data1 = "Hello ".getBytes();
        PoolBuffer pb1 = mockPoolBuffer(data1);
        PoolBuffer pb1Dup = mockPoolBuffer(data1);

        streamBuffer.addIncomingData(0, pb1, false);
        streamBuffer.addIncomingData(0, pb1Dup, false);

        // Depending on implementation, it might store duplicate or not. 
        // TreeMap.put will replace the old one.
        // The contract says: Handles out-of-order frame arrival and reassembly.
        
        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        assertArrayEquals(data1, read.getData());
        assertNull(streamBuffer.readAvailableData());
    }

    @Test
    void testOverlappingData() throws Exception {
        byte[] data1 = "Hello ".getBytes(); // 6 bytes
        byte[] data2 = "lo World".getBytes(); // overlaps "lo "
        PoolBuffer pb1 = mockPoolBuffer(data1);
        PoolBuffer pb2 = mockPoolBuffer(data2);

        streamBuffer.addIncomingData(0, pb1, false);
        streamBuffer.addIncomingData(3, pb2, false);

        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        assertArrayEquals("Hello World".getBytes(), read.getData());
    }

    @Test
    void testFlowControl() throws Exception {
        byte[] largeData = new byte[CAPACITY + 1];
        PoolBuffer pb = mockPoolBuffer(largeData);

        assertThrows(QuicException.class, () -> streamBuffer.addIncomingData(0, pb, false), "Should reject data exceeding capacity");
        verify(pb).release();
        assertEquals(0, streamBuffer.getBufferedBytes());
    }

    @Test
    void testFinHandling() throws Exception {
        byte[] data1 = "Last ".getBytes();
        byte[] data2 = "Data".getBytes();
        PoolBuffer pb1 = mockPoolBuffer(data1);
        PoolBuffer pb2 = mockPoolBuffer(data2);

        streamBuffer.addIncomingData(0, pb1, false);
        streamBuffer.addIncomingData(data1.length, pb2, true);

        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        assertArrayEquals("Last Data".getBytes(), read.getData());
        assertTrue(read.isLast());
    }

    @Test
    void testFinWithEmptyData() throws Exception {
        PoolBuffer pb = mockPoolBuffer(new byte[0]);
        streamBuffer.addIncomingData(10, pb, true);
        
        // Offset 10, but we are at 0.
        assertNull(streamBuffer.readAvailableData());
        
        byte[] data = new byte[10];
        streamBuffer.addIncomingData(0, mockPoolBuffer(data), false);
        
        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        assertEquals(10, read.getData().length);
        assertTrue(read.isLast(), "Should be last because FIN was received for offset 10");
    }

    @Test
    void testFree() throws Exception {
        PoolBuffer pb = mockPoolBuffer("data".getBytes());
        streamBuffer.addIncomingData(0, pb, false);
        assertEquals(4, streamBuffer.getBufferedBytes());
        streamBuffer.free();
        verify(pb).release();
        assertEquals(0, streamBuffer.getBufferedBytes());
    }

    @Test
    void testComplexOverlapping() throws Exception {
        // [A A A] (0, 3)
        //       [B B B] (3, 3) - touching
        //     [C C C] (2, 3) - overlap both A and B
        // [D D D D D D] (0, 6) - covers all
        //         [E E] (5, 2) - overlap end of D and extends

        streamBuffer.addIncomingData(0, mockPoolBuffer(new byte[]{1, 1, 1}), false);
        streamBuffer.addIncomingData(3, mockPoolBuffer(new byte[]{2, 2, 2}), false);
        streamBuffer.addIncomingData(2, mockPoolBuffer(new byte[]{3, 3, 3}), false);
        streamBuffer.addIncomingData(0, mockPoolBuffer(new byte[]{4, 4, 4, 4, 4, 4}), false);
        streamBuffer.addIncomingData(5, mockPoolBuffer(new byte[]{5, 5}), false);

        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        // Expected reassembly:
        // 0-2: from first A (1, 1, 1) or D (4, 4, 4) - implementation adds A then D covers.
        // In current implementation:
        // Add (0, 3, [1,1,1])
        // Add (3, 3, [2,2,2])
        // Add (2, 3, [3,3,3]) -> prev is (0,3), offset 2 < 0+3. newPos = 0 + 3 - 2 = 1.
        //                      data.position(1), offset = 3, data.limit(3 + 3 - 3 = 3).
        //                      So it adds (3, 2, [3,3]) but (3, 3, [2,2,2]) is already there at offset 3.
        //                      Actually addIncomingData uses floorEntry and ceilingKey to trim the NEW fragment.
        
        // Let's re-verify addIncomingData logic for (2, 3, [3,3,3]):
        // prev = (0, 3, [1,1,1]). prev.key + prev.val.rem = 3 > 2.
        // newPos = 0 + 3 - 2 = 1. data.pos(1). offset = 3. data.limit(0 + 3 - 0 = 3).
        // Now data has rem = 2 (indices 1, 2 of original [3,3,3]). offset = 3.
        // next = ceilingKey(3) = 3. offset 3 + 2 > 3. newLimit = 0 + 3 - 3 = 0.
        // data.limit(0). data.rem = 0. Not stored.
        
        // So (2, 3, [3,3,3]) is completely discarded because it's covered by (0,3) and (3,3).
        
        // Expected: 0,1,2 (1,1,1), 3,4,5 (2,2,2), 6 (5)
        // Wait, D (0, 6, [4,4,4,4,4,4])
        // Add (0, 6): prev = (0, 3). prev.key + rem = 3 > 0. newPos = 0 + 3 - 0 = 3. data.pos(3). offset = 3.
        // next = ceilingKey(3) = 3. offset 3 + 3 > 3. newLimit = 3 + 3 - 3 = 3. Wait.
        // newLimit = (int) (data.buf().position() + next - offset) = 3 + 3 - 3 = 3.
        // data.buf().limit(3). data.rem = 0. Discarded.
        
        // The implementation seems to favor existing data and trims new data to fit gaps.
        
        byte[] expected = new byte[]{1, 1, 1, 2, 2, 2, 5};
        assertArrayEquals(expected, read.getData());
    }

    @Test
    void testFragmentInsideAnother() throws Exception {
        streamBuffer.addIncomingData(0, mockPoolBuffer(new byte[]{1, 2, 3, 4, 5}), false);
        streamBuffer.addIncomingData(1, mockPoolBuffer(new byte[]{9, 9, 9}), false); // Inside

        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        assertArrayEquals(new byte[]{1, 2, 3, 4, 5}, read.getData());
    }

    @Test
    void testFragmentCoveringMultipleExisting() throws Exception {
        streamBuffer.addIncomingData(0, mockPoolBuffer(new byte[]{1, 1}), false);
        streamBuffer.addIncomingData(4, mockPoolBuffer(new byte[]{3, 3}), false);
        
        // Gap at 2-3.
        // Add large fragment that covers gap 2-3, fragment 4-5, and then more data at 6-7
        // Offset 1 to 8.
        streamBuffer.addIncomingData(1, mockPoolBuffer(new byte[]{9, 9, 9, 9, 9, 9, 9}), false);
        
        // Stored:
        // (0, 2) -> [1, 1]
        // (2, 2) -> [9, 9] (fills gap 2-3)
        // (4, 2) -> [3, 3]
        // (6, 2) -> [9, 9] (fills gap 6-7) - THIS IS WHAT WE WANT
        
        streamBuffer.addIncomingData(6, mockPoolBuffer(new byte[]{0, 0}), false); 
        
        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        
        // If the bug exists, the fragment (1, 7) was trimmed to (2, 2) because it saw 'next' at 4.
        // So offset 6-7 should be [0, 0] from the later addition.
        // If the bug is fixed, offset 6-7 should be [9, 9].
        
        byte[] expected = new byte[]{1, 1, 9, 9, 3, 3, 9, 9};
        assertArrayEquals(expected, read.getData(), "Should fill ALL gaps covered by the fragment, not just the first one");
    }

    @Test
    void testTouchingFragments() throws Exception {
        streamBuffer.addIncomingData(0, mockPoolBuffer(new byte[]{1, 2}), false);
        streamBuffer.addIncomingData(2, mockPoolBuffer(new byte[]{3, 4}), false);
        
        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        assertArrayEquals(new byte[]{1, 2, 3, 4}, read.getData());
    }

    @Test
    void testOverlappingStart() throws Exception {
        streamBuffer.addIncomingData(2, mockPoolBuffer(new byte[]{3, 4, 5}), false);
        streamBuffer.addIncomingData(0, mockPoolBuffer(new byte[]{1, 2, 9}), false); // Overlaps at offset 2
        
        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        // Implementation favors existing data at 2. So (0, 3) becomes (0, 2)
        assertArrayEquals(new byte[]{1, 2, 3, 4, 5}, read.getData());
    }

    @Test
    void testOverlappingEnd() throws Exception {
        streamBuffer.addIncomingData(0, mockPoolBuffer(new byte[]{1, 2, 3}), false);
        streamBuffer.addIncomingData(2, mockPoolBuffer(new byte[]{9, 4, 5}), false); // Overlaps at offset 2
        
        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        // Implementation favors existing data at 2. So (2, 3) becomes (3, 2)
        assertArrayEquals(new byte[]{1, 2, 3, 4, 5}, read.getData());
    }

    @Test
    void testCrossSectionedFragments() throws Exception {
        // [1, 2, 3] at 0
        //       [5, 6, 7] at 4
        //   [9, 9, 9, 9, 9] at 1
        streamBuffer.addIncomingData(0, mockPoolBuffer(new byte[]{1, 2, 3}), false);
        streamBuffer.addIncomingData(4, mockPoolBuffer(new byte[]{5, 6, 7}), false);
        
        // This covers gap at 3, but also overlaps [1,2,3] and [5,6,7]
        streamBuffer.addIncomingData(1, mockPoolBuffer(new byte[]{9, 9, 9, 9, 9}), false);
        
        // Stored fragments should be:
        // (0, 3) -> [1, 2, 3]
        // (3, 1) -> [9] (the one from offset 1 that was trimmed by (0,3) and (4,3))
        // (4, 3) -> [5, 6, 7]
        
        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        assertArrayEquals(new byte[]{1, 2, 3, 9, 5, 6, 7}, read.getData());
    }

    @Test
    void testDuplicateFragments() throws Exception {
        streamBuffer.addIncomingData(0, mockPoolBuffer(new byte[]{1, 2}), false);
        streamBuffer.addIncomingData(0, mockPoolBuffer(new byte[]{1, 2}), false);
        
        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        assertArrayEquals(new byte[]{1, 2}, read.getData());
        assertNull(streamBuffer.readAvailableData());
    }

    @Test
    void testBufferSegments() throws Exception {
        // Create a large buffer and use segments of it
        byte[] fullData = "0123456789".getBytes();
        
        // Segment 1: "23" at offset 2
        PoolBuffer pb1 = mock(PoolBuffer.class);
        ByteBuffer bb1 = ByteBuffer.wrap(fullData);
        bb1.position(2);
        bb1.limit(4); // "23"
        when(pb1.buf()).thenReturn(bb1);
        when(pb1.borrow()).thenAnswer(_ -> {
            PoolBuffer b = mock(PoolBuffer.class);
            when(b.buf()).thenReturn(bb1.duplicate());
            return b;
        });
        
        // Segment 2: "456" at offset 4
        PoolBuffer pb2 = mock(PoolBuffer.class);
        ByteBuffer bb2 = ByteBuffer.wrap(fullData);
        bb2.position(4);
        bb2.limit(7); // "456"
        when(pb2.buf()).thenReturn(bb2);
        when(pb2.borrow()).thenAnswer(_ -> {
            PoolBuffer b = mock(PoolBuffer.class);
            when(b.buf()).thenReturn(bb2.duplicate());
            return b;
        });

        // Add segment 1 at offset 2 (out of order)
        streamBuffer.addIncomingData(2, pb1, false);
        
        // Add segment 0: "01" at offset 0
        PoolBuffer pb0 = mock(PoolBuffer.class);
        ByteBuffer bb0 = ByteBuffer.wrap(fullData);
        bb0.position(0);
        bb0.limit(2); // "01"
        when(pb0.buf()).thenReturn(bb0);
        streamBuffer.addIncomingData(0, pb0, false);

        // Add segment 2 at offset 4
        streamBuffer.addIncomingData(4, pb2, false);

        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        assertArrayEquals("0123456".getBytes(), read.getData());
        
        assertEquals(0, streamBuffer.getBufferedBytes());
    }

    @Test
    void testBufferedBytesWithSegments() throws Exception {
        byte[] fullData = new byte[100];
        
        // pb1 uses 10 bytes of 100-byte buffer
        PoolBuffer pb1 = mock(PoolBuffer.class);
        ByteBuffer bb1 = ByteBuffer.wrap(fullData);
        bb1.position(10);
        bb1.limit(20);
        when(pb1.buf()).thenReturn(bb1);
        
        streamBuffer.addIncomingData(0, pb1, false);
        
        // Should reflect the actual size of data in the buffer, not capacity
        assertEquals(10, streamBuffer.getBufferedBytes());
        
        streamBuffer.free();
        assertEquals(0, streamBuffer.getBufferedBytes());
    }

    @Test
    void testOverlappingSegmentsInReadAvailableData() throws Exception {
        byte[] fullData = "ABCDEFGHIJ".getBytes(); // 10 bytes
        
        // PB1: offset 0, data "ABC" (pos 0, limit 3)
        PoolBuffer pb1 = mock(PoolBuffer.class);
        ByteBuffer bb1 = ByteBuffer.wrap(fullData);
        bb1.position(0);
        bb1.limit(3);
        when(pb1.buf()).thenReturn(bb1);

        // PB2: offset 2, data "CDE" (pos 2, limit 5)
        // Note: 'C' is at offset 2. Existing data already has 'C' at offset 2.
        // Implementation trims PB2 to start at offset 3.
        PoolBuffer pb2 = mock(PoolBuffer.class);
        ByteBuffer bb2 = ByteBuffer.wrap(fullData);
        bb2.position(2);
        bb2.limit(5);
        when(pb2.buf()).thenReturn(bb2);
        
        streamBuffer.addIncomingData(0, pb1, false);
        streamBuffer.addIncomingData(2, pb2, false);

        StreamBuffer.StreamData read = streamBuffer.readAvailableData();
        assertNotNull(read);
        assertArrayEquals("ABCDE".getBytes(), read.getData());
    }

    @Test
    void testInconsistentFin() throws Exception {
        streamBuffer.addIncomingData(0, mockPoolBuffer(new byte[]{1, 2}), true); // FIN at 2
        
        // What if we receive more data AFTER FIN? QUIC says it's an error if it extends beyond FIN.
        // Implementation check:
        assertThrows(QuicException.class, () -> streamBuffer.addIncomingData(2, mockPoolBuffer(new byte[]{3}), false));
    }

    @Test
    void testGetBufferedBytesTracking() throws Exception {
        byte[] data1 = new byte[100];
        byte[] data2 = new byte[50];
        PoolBuffer pb1 = mockPoolBuffer(data1);
        PoolBuffer pb2 = mockPoolBuffer(data2);

        // Initial state
        assertEquals(0, streamBuffer.getBufferedBytes());

        // Add first fragment
        streamBuffer.addIncomingData(0, pb1, false);
        assertEquals(100, streamBuffer.getBufferedBytes(), "Should track capacity of first fragment");

        // Add second fragment with a gap
        streamBuffer.addIncomingData(150, pb2, false);
        assertEquals(150, streamBuffer.getBufferedBytes(), "Should track total capacity of both fragments");

        // Add overlapping fragment that fills the gap and overlaps both
        // Gap is at 100-150.
        // New fragment from 90 to 160 (length 70).
        // It will overlap pb1 (90-100) -> trimmed.
        // It will fill gap (100-150) -> stored (len 50).
        // It will overlap pb2 (150-160) -> trimmed.
        byte[] dataOverlap = new byte[70];
        PoolBuffer pbOverlap = mockPoolBuffer(dataOverlap);
        streamBuffer.addIncomingData(90, pbOverlap, false);

        // pbOverlap should have been split/borrowed to fill the gap 100-150.
        // The capacity of the borrowed PoolBuffer should be added.
        // Since my mock mockPoolBuffer returns capacity = data.length via ByteBuffer.wrap(data).capacity() implicitly if I used it, 
        // but wait, I didn't mock capacity() explicitly in mockPoolBuffer.
        // Let's check PoolBuffer interface or class.
        
        // In StreamBuffer.java:
        // bufferedBytes += firstPart.buf().capacity();
        // bufferedBytes += data.buf().capacity();
        
        // So it uses buf().capacity(). My mockPoolBuffer sets buf() to return a ByteBuffer.
        // ByteBuffer.wrap(data).capacity() is data.length.
        
        // Expected bufferedBytes: 100 (pb1) + 50 (pb2) + 50 (pbOverlap borrowed part length)
        // pbOverlap (90 to 160, len 70) fills gap 100-150. Piece len is 50.
        assertEquals(100 + 50 + 50, streamBuffer.getBufferedBytes(), "Should include length of split overlapping fragment");

        // Read data
        streamBuffer.readAvailableData(); // Should read 0-160? 
        // nextExpectedOffset was 0.
        // firstKey=0 (pb1). nextExpectedOffset becomes 100. released pb1 (100).
        // nextKey=100 (filler from pbOverlap). nextExpectedOffset becomes 150. released filler (70).
        // nextKey=150 (pb2). nextExpectedOffset becomes 200. released pb2 (50).
        
        // So ALL fragments were contiguous and read.
        assertEquals(0, streamBuffer.getBufferedBytes(), "Should decrease to 0 after reading all contiguous data");

        // Free
        streamBuffer.free();
        assertEquals(0, streamBuffer.getBufferedBytes(), "Should be 0 after free");
    }

    @Test
    void testGetBufferedBytesSequentialReleaseOverlapping() throws Exception {
        // This test specifically targets the sequential release of overlapping buffers.
        // Scenario:
        // 1. Add fragment A: [0, 100)
        // 2. Add fragment B: [50, 150) -> This will be trimmed to [100, 150)
        // 3. Add fragment C: [0, 200) -> This will be trimmed to [150, 200)
        
        byte[] dataA = new byte[100];
        byte[] dataB = new byte[100];
        byte[] dataC = new byte[200];
        
        PoolBuffer pbA = mockPoolBuffer(dataA);
        PoolBuffer pbB = mockPoolBuffer(dataB);
        PoolBuffer pbC = mockPoolBuffer(dataC);
        
        streamBuffer.addIncomingData(0, pbA, false);
        assertEquals(100, streamBuffer.getBufferedBytes());
        
        // B is at 50, length 100. Overlaps A [50, 100).
        // Current implementation:
        // prevEnd = 100. skip = 100 - 50 = 50.
        // dataB.pos(50). offset = 100. dataB.rem = 50.
        // Stored at offset 100.
        streamBuffer.addIncomingData(50, pbB, false);
        // bufferedBytes += pbB.remaining() (which is 50 after trimming)
        assertEquals(100 + 50, streamBuffer.getBufferedBytes());
        
        // C is at 0, length 200.
        // Overlaps A [0, 100). skip = 100. offset = 100. dataC.rem = 100.
        // Now it's at offset 100. next = ceilingKey(100) = 100.
        // Overlaps B piece at 100. offset + rem = 100 + 100 = 200 > 100.
        // currentPortionLen = 100 - 100 = 0.
        // skip = 100 - 100 = 0.
        // dataC.pos stays.
        // Recursive call processFragment(100, dataC, false)
        // Next recursion:
        // prev = (100, [B piece]). prevEnd = 100 + 50 = 150.
        // skip = 150 - 100 = 50.
        // dataC.pos(100 + 50 = 150). offset = 150. dataC.rem = 50.
        // Stored at offset 150.
        streamBuffer.addIncomingData(0, pbC, false);
        // bufferedBytes += pbC.remaining() (which is 50 after trimming)
        assertEquals(100 + 50 + 50, streamBuffer.getBufferedBytes());
        
        // Now read available data.
        // Read A (0-100).
        // In readAvailableData:
        // fragmentA = incomingFragments.remove(0)
        // bufferedBytes -= fragmentA.buf().capacity() (100)
        // nextExpectedOffset becomes 100.
        
        // Fragment B (100-150):
        // fragmentB = incomingFragments.remove(100)
        // bufferedBytes -= fragmentB.buf().capacity() (100)
        // nextExpectedOffset becomes 150.
        
        // Fragment C (150-200):
        // fragmentC = incomingFragments.remove(150)
        // bufferedBytes -= fragmentC.buf().capacity() (200)
        // nextExpectedOffset becomes 200.
        
        streamBuffer.readAvailableData();
        assertEquals(0, streamBuffer.getBufferedBytes(), "Buffered bytes should be 0 after reading everything");
    }

    @Test
    void testGetBufferedBytesMultipleFragmentsSequentialRelease() throws Exception {
        // Scenario where fragments are partially overlapping and released one by one
        // [0, 50) - Fragment A
        // [25, 75) - Fragment B (trimmed to [50, 75))
        // [60, 100) - Fragment C (trimmed to [75, 100))
        
        PoolBuffer pbA = mockPoolBuffer(new byte[50]);
        PoolBuffer pbB = mockPoolBuffer(new byte[50]);
        PoolBuffer pbC = mockPoolBuffer(new byte[40]);
        
        streamBuffer.addIncomingData(0, pbA, false);
        streamBuffer.addIncomingData(25, pbB, false);
        streamBuffer.addIncomingData(60, pbC, false);
        
        // A: 50, B (50-75): 25, C (75-100): 25. Total: 100
        assertEquals(50 + 25 + 25, streamBuffer.getBufferedBytes());
        
        // Read 0-50 (A)
        // nextExpectedOffset is 0.
        // It should take A, release it, and update nextExpectedOffset to 50.
        // Then it should take B, release it, and update nextExpectedOffset to 75.
        // Then it should take C, release it, and update nextExpectedOffset to 100.
        
        // Let's verify readAvailableData logic:
        // while (!incomingFragments.isEmpty()) {
        //   firstOffset = incomingFragments.firstKey(); // 0
        //   if (0 > 0) break;
        //   fragment = incomingFragments.remove(0); // A
        //   bufferedBytes -= fragment.buf().capacity(); // 140 - 50 = 90
        //   ... write ...
        //   nextExpectedOffset += 50; // nextExpectedOffset = 50
        //   fragment.release();
        //   
        //   next loop:
        //   firstOffset = incomingFragments.firstKey(); // 50
        //   if (50 > 50) break;
        //   fragment = incomingFragments.remove(50); // B piece
        //   bufferedBytes -= fragment.buf().capacity(); // 90 - 50 = 40
        //   ... write ...
        //   nextExpectedOffset += 25; // nextExpectedOffset = 75
        //   fragment.release();
        //   
        //   next loop:
        //   firstOffset = incomingFragments.firstKey(); // 75
        //   if (75 > 75) break;
        //   fragment = incomingFragments.remove(75); // C piece
        //   bufferedBytes -= fragment.buf().capacity(); // 40 - 40 = 0
        //   ... write ...
        //   nextExpectedOffset += 25; // nextExpectedOffset = 100
        //   fragment.release();
        // }
        
        streamBuffer.readAvailableData();
        assertEquals(0, streamBuffer.getBufferedBytes());
    }

    @Test
    void testGetBufferedBytesSequentialReleaseWithGaps() throws Exception {
        // [0, 20) - A
        // [40, 60) - B
        // [10, 50) - C. 
        // C overlaps A [10, 20) -> trimmed. 
        // C fills gap [20, 40) -> stored.
        // C overlaps B [40, 50) -> trimmed.
        
        PoolBuffer pbA = mockPoolBuffer(new byte[20]);
        PoolBuffer pbB = mockPoolBuffer(new byte[20]);
        PoolBuffer pbC = mockPoolBuffer(new byte[40]);
        
        streamBuffer.addIncomingData(0, pbA, false);
        streamBuffer.addIncomingData(40, pbB, false);
        assertEquals(40, streamBuffer.getBufferedBytes());
        
        streamBuffer.addIncomingData(10, pbC, false);
        // pbC covers gap [20, 40). Length is 20.
        assertEquals(20 + 20 + 20, streamBuffer.getBufferedBytes());
        
        // Read available data.
        // nextExpectedOffset=0.
        // 1. Takes A (0-20). nextExpectedOffset=20. bufferedBytes -= 20. (60 rem)
        // 2. Takes C piece (20-40). nextExpectedOffset=40. bufferedBytes -= 40. (20 rem)
        // 3. Takes B (40-60). nextExpectedOffset=60. bufferedBytes -= 20. (0 rem)
        
        streamBuffer.readAvailableData();
        assertEquals(0, streamBuffer.getBufferedBytes());
    }

    @Test
    void testStressComplexInteractions() throws Exception {
        // This test simulates a complex sequence of events:
        // out-of-order arrival, multiple gaps, overlapping fragments filling multiple gaps, 
        // and interleaved reads.

        // 1. Initial out-of-order data
        // [10, 20) - Frag A
        // [40, 50) - Frag B
        // [70, 80) - Frag C
        streamBuffer.addIncomingData(10, mockPoolBuffer(new byte[]{10, 11, 12, 13, 14, 15, 16, 17, 18, 19}), false);
        streamBuffer.addIncomingData(40, mockPoolBuffer(new byte[]{40, 41, 42, 43, 44, 45, 46, 47, 48, 49}), false);
        streamBuffer.addIncomingData(70, mockPoolBuffer(new byte[]{70, 71, 72, 73, 74, 75, 76, 77, 78, 79}), false);

        assertEquals(30, streamBuffer.getBufferedBytes());
        assertNull(streamBuffer.readAvailableData(), "No data should be available yet (gap at 0)");

        // 2. Fill the first gap at 0
        // [0, 5) - Frag D
        streamBuffer.addIncomingData(0, mockPoolBuffer(new byte[]{0, 1, 2, 3, 4}), false);
        assertEquals(35, streamBuffer.getBufferedBytes());

        // Read available data (0 to 5)
        StreamBuffer.StreamData read1 = streamBuffer.readAvailableData();
        assertNotNull(read1);
        assertArrayEquals(new byte[]{0, 1, 2, 3, 4}, read1.getData());
        assertEquals(30, streamBuffer.getBufferedBytes()); // A, B, C remain

        // 3. Add a fragment that covers multiple gaps and overlaps existing fragments
        // Current state: [0, 5) delivered. Next expected: 5.
        // Fragments: [10, 20), [40, 50), [70, 80).
        // Gaps at [5, 10), [20, 40), [50, 70).
        
        // Add Frag E: [2, 75)
        // Overlaps [2, 5) - already delivered -> skip
        // Fills gap [5, 10) -> store
        // Overlaps [10, 20) -> trim
        // Fills gap [20, 40) -> store
        // Overlaps [40, 50) -> trim
        // Fills gap [50, 70) -> store
        // Overlaps [70, 75) -> trim
        
        byte[] dataE = new byte[73]; // length from offset 2 to 75
        for (int i = 0; i < 73; i++) dataE[i] = (byte) (i + 2);
        streamBuffer.addIncomingData(2, mockPoolBuffer(dataE), false);

        assertEquals(78, streamBuffer.getBufferedBytes());

        // Now read all available data
        // nextExpected: 5.
        // Should read: 
        // [5, 10) from E
        // [10, 20) from A
        // [20, 40) from E
        // [40, 50) from B
        // [50, 70) from E
        // [70, 80) from C
        // Total bytes read: 75.
        
        StreamBuffer.StreamData read2 = streamBuffer.readAvailableData();
        assertNotNull(read2);
        assertEquals(75, read2.getData().length);
        assertEquals(0, streamBuffer.getBufferedBytes());

        // Verify the content of read2
        byte[] expectedRead2 = new byte[75];
        for (int i = 0; i < 75; i++) {
            expectedRead2[i] = (byte) (i + 5);
        }
        assertArrayEquals(expectedRead2, read2.getData());

        // 4. Add more data and a FIN
        streamBuffer.addIncomingData(80, mockPoolBuffer(new byte[]{80, 81}), false);
        streamBuffer.addIncomingData(85, mockPoolBuffer(new byte[]{}), true); // FIN at 85
        
        assertEquals(2, streamBuffer.getBufferedBytes());
        
        StreamBuffer.StreamData read3 = streamBuffer.readAvailableData();
        assertNotNull(read3);
        assertArrayEquals(new byte[]{80, 81}, read3.getData());
        assertFalse(read3.isLast(), "Not last because gap at 82-85");
        
        // Fill the final gap
        streamBuffer.addIncomingData(82, mockPoolBuffer(new byte[]{82, 83, 84}), false);
        StreamBuffer.StreamData read4 = streamBuffer.readAvailableData();
        assertNotNull(read4);
        assertArrayEquals(new byte[]{82, 83, 84}, read4.getData());
        assertTrue(read4.isLast(), "Should be last now");
        
        assertEquals(0, streamBuffer.getBufferedBytes());
    }
}
