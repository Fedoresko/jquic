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
package org.jquic.quic.buffers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class NonWrappingChunkedOutputStreamWithAmendmentsTest {
    private BufferPool myPool;

    @BeforeEach
    public void setup() {
        myPool = mock(BufferPool.class);
    }

    @Test
    public void testBasicChunking() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        int chunkSize = 10;
        
        when(myPool.requestWriteBuffer()).thenReturn(new RootPoolBuffer(buffer, myPool, true));
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, chunkSize, 0, (buf, _, _) -> buf.duplicate());
        
        byte[] data = pattern(25, 1);
        stream.write(data);
        
        assertEquals(25, stream.getPos());
        
        // Should have 2 ready chunks of 10 bytes each
        PoolBuffer p1 = stream.pollReadyChunk();
        assertContent(pattern(10, 1), p1);
        
        PoolBuffer p2 = stream.pollReadyChunk();
        assertContent(pattern(10, 11), p2);
        
        assertNull(stream.pollReadyChunk());
        
        stream.flush();
        PoolBuffer p3 = stream.pollReadyChunk();
        assertContent(pattern(5, 21), p3);
    }

    private byte[] pattern(int len, int startValue) {
        byte[] data = new byte[len];
        for (int i = 0; i < len; i++) data[i] = (byte) (startValue + i);
        return data;
    }

    private void assertContent(byte[] expected, PoolBuffer actual) {
        assertNotNull(actual);
        ByteBuffer buf = actual.buf();
        assertEquals(expected.length, buf.remaining());
        for (int i = 0; i < expected.length; i++) {
            assertEquals(expected[i], buf.get(buf.position() + i), "Mismatch at index " + i);
        }
    }

    @Test
    public void testNewBufferAllocationWhenFull() throws IOException {
        ByteBuffer buffer1 = ByteBuffer.allocate(32);
        ByteBuffer buffer2 = ByteBuffer.allocate(32);
        int chunkSize = 10;

        when(myPool.requestWriteBuffer())
            .thenReturn(new RootPoolBuffer(buffer1, myPool, true))
            .thenReturn(new RootPoolBuffer(buffer2, myPool, true));
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, chunkSize, 0, (buf, offset, isFinal) -> buf.duplicate());

        // Write 30 bytes (3 chunks of 10)
        stream.write(pattern(30, 1));
        assertEquals(30, stream.getPos());
        
        // 2 bytes left in buffer1.
        stream.write(pattern(5, 31));
        
        assertEquals(35, stream.getPos());

        stream.flush();

        // Chunks should be: 10, 10, 10, 2 (remaining of buf1), 3 (start of buf2)
        PoolBuffer p1 = stream.pollReadyChunk();
        PoolBuffer p2 = stream.pollReadyChunk();
        PoolBuffer p3 = stream.pollReadyChunk();
        PoolBuffer p4 = stream.pollReadyChunk();
        PoolBuffer p5 = stream.pollReadyChunk();

        assertContent(pattern(10, 1), p1);
        assertContent(pattern(10, 11), p2);
        assertContent(pattern(10, 21), p3);
        assertContent(pattern(2, 31), p4);
        assertContent(pattern(3, 33), p5);
        
        assertSame(buffer1.array(), p1.buf().array());
        assertSame(buffer1.array(), p4.buf().array());
        assertSame(buffer2.array(), p5.buf().array());

        assertNull(stream.pollReadyChunk());
        stream.close();
    }

    @Test
    public void testTrailingPadding() throws IOException {
        ByteBuffer b1 = ByteBuffer.allocate(32);
        ByteBuffer b2 = ByteBuffer.allocate(32);
        int chunkSize = 10;
        int trailingPadding = 5;

        when(myPool.requestWriteBuffer()).thenReturn(new RootPoolBuffer(b1, myPool, true))
                .thenReturn(new RootPoolBuffer(b2, myPool, true));
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, chunkSize, trailingPadding, (buf, offset, isFinal) -> buf.duplicate());

        // Buffer capacity 32. Effective capacity 32 - 5 = 27.
        // Chunk 0: [0, 10), gap [10, 15)
        // Chunk 1: [15, 25), gap [25, 30)
        // Next chunk would start at 30, but only 2 bytes left in buffer.
        // atTheBufferEdge() will be triggered when remaining <= 5.
        
        stream.write(pattern(25, 1));
        assertEquals(25, stream.getPos());
        
        // Write 5 more bytes.
        // First 2 bytes go to b1[25, 27). Edge hit at 27 (remaining 5).
        // triggerCallback for Chunk 2 (from 15 to 27? NO, chunkStart was 30? Wait)
        // Let's re-trace.
        // Chunk 0: start 0, end 10. Advance 5. Next start 15.
        // Chunk 1: start 15, end 25. Advance 5. Next start 30.
        // Now at 30. Remaining 2. Effective capacity hit!
        // Wait, when writing the 25 bytes:
        // Loop 1: 10 bytes. pos 10. callback. nextStart 15.
        // Loop 2: 10 bytes. pos 25. callback. nextStart 30.
        // Loop 3: remaining data is 5 bytes. 
        //   spaceLim = 32 - 30 - 5 = -3 -> 0.
        //   bytesToCopy = 0.
        //   triggerCallback because atTheBufferEdge (2 <= 5).
        //   In triggerCallback: chunkWrappedLen = 0 (chunkStart 30, position 30).
        //   advance = 5. remaining is 2. 2 <= 5 + 5 is true.
        //   Request new buffer b2.
        //   Loop 3 continues: 5 bytes into b2. pos 5.
        
        stream.write(pattern(5, 26));
        
        assertEquals(30, stream.getPos());
        
        PoolBuffer p1 = stream.pollReadyChunk(); // Chunk 0: 1-10
        PoolBuffer p2 = stream.pollReadyChunk(); // Chunk 1: 11-20
        // Chunk from Loop 3 triggerCallback was empty, so not offered.
        
        stream.flush();
        PoolBuffer p3 = stream.pollReadyChunk(); // Chunk 2: 21-30 (all in b2)
        
        assertContent(pattern(10, 1), p1);
        assertContent(pattern(10, 11), p2);
        assertContent(pattern(10, 21), p3);
        assertNull(stream.pollReadyChunk());

        assertSame(b1.array(), p1.buf().array());
        assertSame(b1.array(), p2.buf().array());
        assertSame(b2.array(), p3.buf().array());
        
        // Check gaps in b1 are untouched (or at least contain what they should)
        // Gaps are [10, 15) and [25, 32)
        for (int i = 10; i < 15; i++) assertEquals(0, b1.get(i));
        for (int i = 25; i < 32; i++) assertEquals(0, b1.get(i));
    }

    @Test
    public void testAmendAtPos() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        when(myPool.requestWriteBuffer()).thenReturn(new RootPoolBuffer(buffer, myPool, true));
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, 10, 0, (buf, offset, isFinal) -> buf.duplicate());
        
        stream.write(new byte[]{1, 2, 3, 4, 5});
        int pos = stream.getPos(); // 5
        stream.write(new byte[]{6, 7, 8, 9, 10});
        
        stream.amendAtPos(pos - 3, dos -> dos.write(new byte[]{100, 101}));
        
        assertEquals(10, stream.getPos());
        
        stream.flush();
        PoolBuffer p1 = stream.pollReadyChunk();
        ByteBuffer b = p1.buf();
        assertEquals(1, b.get(0));
        assertEquals(2, b.get(1));
        assertEquals((byte)100, b.get(2));
        assertEquals((byte)101, b.get(3));
        assertEquals(5, b.get(4));
    }

    @Test
    public void testReadyContentFrom() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        when(myPool.requestWriteBuffer()).thenReturn(new RootPoolBuffer(buffer, myPool, true));
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, 10, 2, (buf, offset, isFinal) -> buf.duplicate());
        
        stream.write(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15});
        
        // Logical pos 5 is value 6.
        Iterator<ByteBuffer> it = stream.readyContentFrom(5).iterator();
        assertTrue(it.hasNext());
        ByteBuffer b1 = it.next(); // Should be 6, 7, 8, 9, 10 (end of first chunk)
        assertEquals(5, b1.remaining());
        assertEquals(6, b1.get());
        
        assertTrue(it.hasNext());
        ByteBuffer b2 = it.next(); // Should be 11, 12, 13, 14, 15
        assertEquals(5, b2.remaining());
        assertEquals(11, b2.get());
        
        assertFalse(it.hasNext());
    }

    @Test
    public void testChunkWrapperWithHeadersAndPadding() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        // Clear buffer to ensure zeros in gaps
        for (int i = 0; i < 100; i++) buffer.put(i, (byte) 0);
        
        when(myPool.requestWriteBuffer()).thenReturn(new RootPoolBuffer(buffer.position(2), myPool, true));
        
        // Wrapper that adds 2 bytes header "<<"
        ChunkedOutputStreamWithAmendments.ChunkWrapper wrapper = (buf, offset, isFinal) -> {
            int start = buf.position();
            int end = buf.limit();
            buffer.put(start - 2, (byte)'<');
            buffer.put(start - 1, (byte)'<');
            return buffer.duplicate().position(start - 2).limit(end);
        };
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, 10, 5, wrapper);
        
        stream.write(new byte[]{1, 2, 3, 4, 5});
        stream.flush();
        
        PoolBuffer p1 = stream.pollReadyChunk();
        ByteBuffer b1 = p1.buf();
        assertEquals(7, b1.remaining());
        assertEquals('<', b1.get());
        assertEquals('<', b1.get());
        assertEquals(1, b1.get());
        
        // Gap of 5 bytes (trailingPadding) should be at indices 7, 8, 9, 10, 11
        for (int i = 7; i < 12; i++) {
            assertEquals(0, buffer.get(i), "Gap at index " + i + " should be 0");
        }
        
        stream.write(new byte[]{6, 7, 8});
        stream.flush();
        
        PoolBuffer p2 = stream.pollReadyChunk();
        ByteBuffer b2 = p2.buf();
        assertEquals(5, b2.remaining()); // 2 header + 3 data
        assertEquals('<', b2.get());
        assertEquals('<', b2.get());
        assertEquals(6, b2.get());
    }

    @Test
    public void testLargeWriteSpanningMultipleChunks() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        when(myPool.requestWriteBuffer()).thenReturn(new RootPoolBuffer(buffer, myPool, true));
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, 10, 0, (buf, offset, isFinal) -> buf.duplicate());
        
        byte[] data = new byte[25];
        for (int i = 0; i < 25; i++) data[i] = (byte) i;
        
        stream.write(data);
        stream.flush();
        
        assertEquals(10, stream.pollReadyChunk().buf().remaining());
        assertEquals(10, stream.pollReadyChunk().buf().remaining());
        assertEquals(5, stream.pollReadyChunk().buf().remaining());
        assertNull(stream.pollReadyChunk());
    }

    @Test
    public void testSetChunkConsumer() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        when(myPool.requestWriteBuffer()).thenReturn(new RootPoolBuffer(buffer, myPool, true));
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, 10, 0, (buf, offset, isFinal) -> buf.duplicate());
        
        List<PoolBuffer> consumed = new ArrayList<>();
        stream.setChunkConsumer(consumed::add);
        
        stream.write(pattern(15, 1));
        assertEquals(1, consumed.size());
        assertContent(pattern(10, 1), consumed.get(0));
        
        stream.flush();
        assertEquals(2, consumed.size());
        assertContent(pattern(5, 11), consumed.get(1));
    }

    @Test
    public void testIllegalAmendments() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        when(myPool.requestWriteBuffer()).thenReturn(new RootPoolBuffer(buffer, myPool, true));
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, 10, 0, (buf, offset, isFinal) -> buf.duplicate());
        
        stream.write(new byte[20]);
        
        // Current logical offset is 20.
        assertThrows(IllegalArgumentException.class, () -> stream.amendAtPos(-1, dos -> dos.write(1)));
        assertThrows(IllegalArgumentException.class, () -> stream.amendAtPos(20, dos -> dos.write(1)));
        assertThrows(IllegalArgumentException.class, () -> stream.amendAtPos(21, dos -> dos.write(1)));
    }

    @Test
    public void testCloseReleasesBuffer() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        RootPoolBuffer root = spy(new RootPoolBuffer(buffer, myPool, true));
        when(myPool.requestWriteBuffer()).thenReturn(root);
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, 10, 0, (buf, offset, isFinal) -> buf.duplicate());
        
        stream.write(new byte[5]);
        assertFalse(stream.isClosed());
        
        stream.close();
        assertTrue(stream.isClosed());
        
        // Verify release was called. RootPoolBuffer.release() is what returns to pool.
        verify(root, atLeastOnce()).release();
    }

    @Test
    public void testDataOutputStreamMethods() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        when(myPool.requestWriteBuffer()).thenReturn(new RootPoolBuffer(buffer, myPool, true));
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, 20, 0, (buf, offset, isFinal) -> buf.duplicate());
        
        stream.writeInt(0x12345678);
        stream.writeShort(0xABCD);
        stream.writeUTF("Hello");
        
        stream.flush();
        PoolBuffer p = stream.pollReadyChunk();
        ByteBuffer b = p.buf();
        
        assertEquals(0x12345678, b.getInt());
        assertEquals((short)0xABCD, b.getShort());
        // UTF is length (short) + bytes
        assertEquals(5, b.getShort());
        byte[] utfBytes = new byte[5];
        b.get(utfBytes);
        assertEquals("Hello", new String(utfBytes));
    }

    @Test
    public void testAmendMultipleTimes() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        when(myPool.requestWriteBuffer()).thenReturn(new RootPoolBuffer(buffer, myPool, true));
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, 10, 0, (buf, offset, isFinal) -> buf.duplicate());
        
        stream.write(new byte[]{0, 0, 0, 0, 0}); // pos 0..4
        stream.write(new byte[]{1, 1, 1, 1, 1}); // pos 5..9
        
        stream.amendAtPos(0, dos -> dos.write(new byte[]{10, 20}));
        stream.amendAtPos(1, dos -> dos.write(new byte[]{30}));
        
        stream.flush();
        PoolBuffer p1 = stream.pollReadyChunk();
        ByteBuffer b = p1.buf();
        assertEquals(10, b.get(0));
        assertEquals(30, b.get(1));
        assertEquals(0, b.get(2));
    }

    @Test
    public void testAmendAfterFlush() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        when(myPool.requestWriteBuffer()).thenReturn(new RootPoolBuffer(buffer, myPool, true));
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, 10, 0, (buf, offset, isFinal) -> buf.duplicate());
        
        stream.write(new byte[]{1, 2, 3, 4, 5});
        stream.flush(); // Chunk 0 is 5 bytes. gaps: {5 -> nextStart}
        
        stream.write(new byte[]{6, 7, 8, 9, 10, 11, 12, 13, 14, 15}); // Logical pos 5..14
        
        // This should work logically, but might fail due to implementation bug in getLogicalPosition
        // Logical pos 7 is in the second chunk.
        stream.amendAtPos(7, dos -> dos.write(new byte[]{99}));
        
        stream.flush();
        stream.pollReadyChunk(); // First chunk
        PoolBuffer p2 = stream.pollReadyChunk(); // Second chunk
        assertEquals(99, p2.buf().get(p2.buf().position() + 2)); // 7 - 5 = 2
    }

    @Test
    public void testAmendAfterSmallChunkFails() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        when(myPool.requestWriteBuffer()).thenReturn(new RootPoolBuffer(buffer, myPool, true));
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, 10, 0, (buf, offset, isFinal) -> buf.duplicate());
        
        stream.write(pattern(5, 1));
        stream.flush(); // Chunk 0 is 5 bytes. gaps: {5 -> nextStart}
        
        stream.write(pattern(10, 6)); // Logical offset 15.
        stream.write(pattern(10, 16)); // Logical offset 25.
        
        // Logical pos 17 is in the third chunk (5 + 10 + 2).
        // It will fail because getLogicalPosition assumes all previous chunks are chunkSize(10).
        assertThrows(IndexOutOfBoundsException.class, () -> stream.amendAtPos(17, dos -> dos.write(1)));
    }

    @Test
    public void testGoBackAfterBufferAllocationAmendsWrongBuffer() throws IOException {
        ByteBuffer b1 = ByteBuffer.allocate(32);
        ByteBuffer b2 = ByteBuffer.allocate(32);
        when(myPool.requestWriteBuffer()).thenReturn(new RootPoolBuffer(b1, myPool, true)).thenReturn(new RootPoolBuffer(b2, myPool, true));
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, 10, 0, (buf, offset, isFinal) -> buf.duplicate());
        
        stream.write(pattern(32, 1));
        stream.write(pattern(5, 33)); // Triggers new buffer b2
        
        // amendAtPos(5) should amend b1, but since lastBufferLogicalStart is not updated,
        // it amends b2 at position 5!
        assertThrows(IllegalArgumentException.class, () -> stream.amendAtPos(5, dos -> dos.write(new byte[]{99})));
    }

    @Test
    public void testComplexVaryingMarginsAndPadding() throws IOException {
        int bufferSize = 64;
        int chunkSize = 16;
        int trailingPadding = 8;

        ByteBuffer b1 = ByteBuffer.allocate(bufferSize);
        ByteBuffer b2 = ByteBuffer.allocate(bufferSize);

        // Pre-fill buffers with 0xEE to distinguish from gaps (0x00)
        for (int i = 0; i < bufferSize; i++) {
            b1.put(i, (byte) 0xEE);
            b2.put(i, (byte) 0xEE);
        }

        b1.position(10);
        b2.position(10);

        when(myPool.requestWriteBuffer())
                .thenReturn(new RootPoolBuffer(b1, myPool, true))
                .thenReturn(new RootPoolBuffer(b2, myPool, true));

        // Wrapper adds a header of size 2 or 4.
        ChunkedOutputStreamWithAmendments.ChunkWrapper wrapper = (buf, offset, isFinal) -> {
            int headerSize = (offset / chunkSize) % 2 == 0 ? 2 : 4;
            int start = buf.position();
            int end = buf.limit();
            
            ByteBuffer underlying = (b1.array() == buf.array()) ? b1 : b2;

            int oldPos = underlying.position();
            underlying.position(start - headerSize);
            byte headerByte = (headerSize == 2) ? (byte) 0xAA : (byte) 0xBB;
            for (int i = 0; i < headerSize; i++) underlying.put(start - headerSize + i, headerByte);
            underlying.position(oldPos);
            return underlying.duplicate().position(start - headerSize).limit(end);
        };

        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, chunkSize, trailingPadding, wrapper);

        // Write 40 bytes. Chunk 0 (16), Chunk 1 (16) in b1. Chunk 2 (8) in b2.
        stream.write(pattern(40, 1));
        
        // Verify chunks
        PoolBuffer p0 = stream.pollReadyChunk();
        assertNotNull(p0);
        assertEquals(18, p0.buf().remaining()); 
        assertEquals((byte)0xAA, p0.buf().get(p0.buf().position()));
        PoolBuffer p0_data = p0.borrow();
        p0_data.buf().position(p0.buf().position() + 2);
        assertContent(pattern(16, 1), p0_data);
        p0_data.release();
        assertEquals((byte)1, p0.buf().get(p0.buf().position() + 2));
        assertEquals((byte)16, p0.buf().get(p0.buf().position() + 17));

        PoolBuffer p1 = stream.pollReadyChunk();
        assertNotNull(p1);
        assertEquals(20, p1.buf().remaining());
        assertEquals((byte)0xBB, p1.buf().get(p1.buf().position()));
        assertEquals((byte)17, p1.buf().get(p1.buf().position() + 4));
        
        stream.flush();
        PoolBuffer p2 = stream.pollReadyChunk();
        assertNotNull(p2);
        assertEquals(10, p2.buf().remaining()); // Header 2 + Data 8
        assertEquals((byte)0xAA, p2.buf().get(p2.buf().position()));
        assertEquals((byte)33, p2.buf().get(p2.buf().position() + 2));

        // Verify physical positions in b1
        // Chunk 0 data: b1[10, 26)
        for (int i = 0; i < 16; i++) assertEquals((byte)(i + 1), b1.get(10 + i));
        // Chunk 1 data: b1[36, 52)
        for (int i = 0; i < 16; i++) assertEquals((byte)(i + 17), b1.get(36 + i));
        
        // Gap in b1 between chunks: [26, 32). Header for chunk 1 was at [32, 36).
        // So [26, 32) should be 0xEE (gap - untouched)
        for (int i = 26; i < 32; i++) assertEquals((byte)0xEE, b1.get(i));

        // Document lastBufferLogicalStart bug: amendment targets wrong buffer
        assertThrows(IllegalArgumentException.class,() -> stream.amendAtPos(5, dos -> dos.write(new byte[]{99})));
    }

    @Test
    public void testReadyContentFromWithVaryingMargins() throws IOException {
        int bufferSize = 100;
        int chunkSize = 10;
        int trailingPadding = 5;
        ByteBuffer buffer = ByteBuffer.allocate(bufferSize);
        buffer.position(10);
        when(myPool.requestWriteBuffer()).thenReturn(new RootPoolBuffer(buffer, myPool, true));

        ChunkedOutputStreamWithAmendments.ChunkWrapper wrapper = (buf, offset, isFinal) -> {
            int start = buf.position();
            buffer.put(start - 2, (byte)'<');
            buffer.put(start - 1, (byte)'<');
            return buffer.duplicate().position(start - 2).limit(buf.limit());
        };

        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, chunkSize, trailingPadding, wrapper);
        byte[] data = new byte[15];
        for (int i = 0; i < 15; i++) data[i] = (byte)(i + 1);
        stream.write(data);
        
        List<Byte> result = new ArrayList<>();
        stream.readyContentFrom(5).forEach(buf -> {
            while (buf.hasRemaining()) result.add(buf.get());
        });
        
        assertEquals(10, result.size());
        assertEquals(6, (int)result.get(0));
        assertEquals(15, (int)result.get(9));
        for (Byte b : result) assertNotEquals((byte)'<', b.byteValue());
    }

    @Test
    public void testVaryingMarginsAndPaddingExhaustingBuffer() throws IOException {
        int bufferSize = 64;
        int chunkSize = 10;
        int trailingPadding = 20;
        ByteBuffer b1 = ByteBuffer.allocate(bufferSize);
        ByteBuffer b2 = ByteBuffer.allocate(bufferSize);
        when(myPool.requestWriteBuffer()).thenReturn(new RootPoolBuffer(b1, myPool, true)).thenReturn(new RootPoolBuffer(b2, myPool, true));
        
        ChunkedOutputStreamWithAmendments.ChunkWrapper wrapper = (buf, offset, isFinal) -> 
            buf.duplicate().position(buf.position() - 10);
        
        b1.position(20);
        b2.position(20);
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, chunkSize, trailingPadding, wrapper);
        
        stream.write(pattern(10, 1)); // Chunk 0
        stream.write(pattern(10, 11)); // Chunk 1 (should be in b2)
        
        assertEquals(20, stream.getPos());
        PoolBuffer p0 = stream.pollReadyChunk();
        PoolBuffer p1 = stream.pollReadyChunk();
        
        assertNotNull(p0);
        assertEquals(20, p0.buf().remaining()); // 10 header + 10 data
        assertNotNull(p1);
        assertEquals(20, p1.buf().remaining());
        
        assertSame(b1.array(), p0.buf().array());
        assertSame(b2.array(), p1.buf().array());
    }

    @Test
    public void testMultiBufferWithVaryingMarginsAndPadding() throws IOException {
        // This test will write data that spans 3 physical buffers with varying headers and padding
        int bufferSize = 64;
        int chunkSize = 10;
        int trailingPadding = 6;
        
        ByteBuffer b1 = ByteBuffer.allocate(bufferSize);
        ByteBuffer b2 = ByteBuffer.allocate(bufferSize);
        ByteBuffer b3 = ByteBuffer.allocate(bufferSize);
        
        // Start at position 10 to leave space for headers
        b1.position(10);
        b2.position(10);
        b3.position(10);

        when(myPool.requestWriteBuffer())
            .thenReturn(new RootPoolBuffer(b1, myPool, true))
            .thenReturn(new RootPoolBuffer(b2, myPool, true))
            .thenReturn(new RootPoolBuffer(b3, myPool, true));
            
        // Wrapper: alternating 2 and 4 byte headers
        ChunkedOutputStreamWithAmendments.ChunkWrapper wrapper = (buf, offset, isFinal) -> {
            int headerLen = (offset / chunkSize) % 2 == 0 ? 2 : 4;
            ByteBuffer underlying = (buf.array() == b1.array()) ? b1 : (buf.array() == b2.array() ? b2 : b3);
            
            int start = buf.position();
            int end = buf.limit();
            underlying.position(start - headerLen);
            for (int i = 0; i < headerLen; i++) underlying.put((byte) 0xFF);
            return underlying.duplicate().position(start - headerLen).limit(end);
        };
        
        ChunkedOutputStreamWithAmendments stream = ChunkedOutputStreamWithAmendments.createNonWrapping(myPool, chunkSize, trailingPadding, wrapper);
        
        // Write 45 bytes.
        stream.write(pattern(45, 1));
        stream.flush();
        
        // Polling chunks
        PoolBuffer p0 = stream.pollReadyChunk(); // Chunk 0 (10 bytes data)
        PoolBuffer p1 = stream.pollReadyChunk(); // Chunk 1 (10 bytes data)
        PoolBuffer p2 = stream.pollReadyChunk(); // Chunk 2 (10 bytes data)
        PoolBuffer p3 = stream.pollReadyChunk(); // Chunk 3 (10 bytes data)
        PoolBuffer p4 = stream.pollReadyChunk(); // Chunk 4 (5 bytes data)
        
        // Verify Chunk 0: b1[10, 20), wrapped [8, 20)
        assertEquals(12, p0.buf().remaining());
        assertEquals((byte)0xFF, p0.buf().get(p0.buf().position()));
        PoolBuffer p0_data = p0.borrow(); p0_data.buf().position(p0.buf().position() + 2);
        assertContent(pattern(10, 1), p0_data); p0_data.release();
        
        // Verify Chunk 1: b1[30, 40), wrapped [26, 40)
        // Advance for p0: (12-10)+6 = 8. position = 20 + 8 = 28. Next chunk start 28.
        // Wait, chunkStart 28. headerLen 4. Physical data starts at 32. 
        // 32-28 = 4 (header). Wrapped [28, 42). 
        // Wait, my manual trace said header 4. so data starts at 32.
        // Let's re-verify.
        assertEquals(14, p1.buf().remaining());
        assertEquals((byte)0xFF, p1.buf().get(p1.buf().position()));
        PoolBuffer p1_data = p1.borrow(); p1_data.buf().position(p1.buf().position() + 4);
        assertContent(pattern(10, 11), p1_data); p1_data.release();

        // Verify Chunk 2: b2[10, 20), wrapped [8, 20)
        assertEquals(12, p2.buf().remaining());
        PoolBuffer p2_data = p2.borrow(); p2_data.buf().position(p2.buf().position() + 2);
        assertContent(pattern(10, 21), p2_data); p2_data.release();

        // Verify Chunk 3
        assertEquals(14, p3.buf().remaining());
        PoolBuffer p3_data = p3.borrow(); p3_data.buf().position(p3.buf().position() + 4);
        assertContent(pattern(10, 31), p3_data); p3_data.release();

        // Verify Chunk 4
        assertEquals(7, p4.buf().remaining());
        PoolBuffer p4_data = p4.borrow(); p4_data.buf().position(p4.buf().position() + 2);
        assertContent(pattern(5, 41), p4_data); p4_data.release();
        
        assertNull(stream.pollReadyChunk());
    }
}
