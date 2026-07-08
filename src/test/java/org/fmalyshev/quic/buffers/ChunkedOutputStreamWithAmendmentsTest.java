package org.fmalyshev.quic.buffers;

import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.function.BiFunction;

import static org.junit.jupiter.api.Assertions.*;

public class ChunkedOutputStreamWithAmendmentsTest {

    @Test
    public void testSmallDataFramesWithWrapping() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        int chunkSize = 10;
        
        // Wrapper adds '[' before and ']' after each chunk in-place (zero-copy)
        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> {
            int dataStart = buf.position();
            int dataEnd = buf.limit();
            
            // Go back to write '['
            buf.position(dataStart - 1);
            buf.put((byte) '[');
            
            // Go forward to write ']'
            buf.limit(dataEnd + 1);
            buf.position(dataEnd);
            buf.put((byte) ']');
            
            // Prepare result: the whole wrapped chunk (a duplicate slice of the original buffer)
            ByteBuffer wrapped = buf.duplicate();
            wrapped.position(dataStart - 1);
            wrapped.limit(dataEnd + 1);
            
            // Adjust buffer for next chunk: skip 1 byte for next header
            buf.limit(buf.capacity());
            buf.position(dataEnd + 2); 
            return wrapped;
        };

        // Before starting, we must reserve space for the first header
        buffer.position(1);
        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);
        
        // Write 25 bytes -> 3 chunks (10, 10, 5)
        for (int i = 0; i < 25; i++) {
            stream.write(i);
        }
        stream.close();

        List<ByteBuffer> chunks = new ArrayList<>();
        stream.readyChunks().forEach(chunks::add);

        assertEquals(3, chunks.size());
        
        // Chunk 1: [ + 10 bytes + ]
        ByteBuffer c1 = chunks.get(0);
        assertEquals(12, c1.remaining());
        assertEquals((byte) '[', c1.get());
        for (int i = 0; i < 10; i++) assertEquals((byte) i, c1.get());
        assertEquals((byte) ']', c1.get());

        // Chunk 2: [ + 10 bytes + ]
        ByteBuffer c2 = chunks.get(1);
        assertEquals(12, c2.remaining());
        assertEquals((byte) '[', c2.get());
        for (int i = 10; i < 20; i++) assertEquals((byte) i, c2.get());
        assertEquals((byte) ']', c2.get());

        // Chunk 3: [ + 5 bytes + ]
        ByteBuffer c3 = chunks.get(2);
        assertEquals(7, c3.remaining());
        assertEquals((byte) '[', c3.get());
        for (int i = 20; i < 25; i++) assertEquals((byte) i, c3.get());
        assertEquals((byte) ']', c3.get());
        
        // Verify that all data is in the SAME buffer and nothing was re-allocated
        for (ByteBuffer c : chunks) {
            assertTrue(c.hasArray());
            assertSame(buffer.array(), c.array());
        }
    }

    @Test
    public void testAmendingAlreadyWrappedChunks() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        int chunkSize = 10;
        
        // Simple wrapper: returns a duplicate of the chunk slice
        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> {
            ByteBuffer res = buf.duplicate();
            int limit = buf.limit();
            buf.limit(buf.capacity());
            buf.position(limit);
            return res;
        };

        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);
        
        // Write 15 bytes -> 1 full chunk (10) and 1 partial (5)
        stream.write(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14});
        
        int posToAmend = 5; 
        stream.amendAtPos(posToAmend, dos -> dos.write(new byte[]{99, 98, 97})); // Amend positions 5, 6, 7
        
        stream.close();

        List<ByteBuffer> chunks = new ArrayList<>();
        stream.readyChunks().forEach(chunks::add);

        assertEquals(2, chunks.size());
        
        ByteBuffer c1 = chunks.get(0).duplicate();
        assertEquals(0, c1.get()); // 0
        assertEquals(1, c1.get()); // 1
        assertEquals(2, c1.get()); // 2
        assertEquals(3, c1.get()); // 3
        assertEquals(4, c1.get()); // 4
        assertEquals(99, c1.get()); // 5 amended
        assertEquals(98, c1.get()); // 6 amended
        assertEquals(97, c1.get()); // 7 amended
        assertEquals(8, c1.get()); // 8
        assertEquals(9, c1.get()); // 9
    }

    @Test
    public void testAmendingOnChunkBoundary() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        int chunkSize = 10;
        
        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> {
            ByteBuffer res = buf.duplicate();
            int limit = buf.limit();
            buf.limit(buf.capacity());
            buf.position(limit);
            return res;
        };

        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);
        
        // Write 20 bytes -> 2 full chunks
        stream.write(new byte[20]);
        
        // Amend across boundary
        stream.amendAtPos(9, dos -> dos.write(new byte[]{1, 2})); // Writes to index 9 (end of chunk 1) and 10 (start of chunk 2)
        
        stream.close();

        List<ByteBuffer> chunks = new ArrayList<>();
        stream.readyChunks().forEach(chunks::add);

        assertEquals(2, chunks.size());
        
        ByteBuffer c1 = chunks.get(0).duplicate();
        c1.position(9);
        assertEquals(1, c1.get());
        
        ByteBuffer c2 = chunks.get(1).duplicate();
        assertEquals(2, c2.get());
    }

    @Test
    public void testCrossBoundaryLongerTypes() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        int chunkSize = 10;
        
        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> {
            ByteBuffer res = buf.duplicate();
            int limit = buf.limit();
            buf.limit(buf.capacity());
            buf.position(limit);
            return res;
        };

        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);
        
        // Write 20 bytes (2 chunks)
        stream.write(new byte[20]);
        
        // Amend cross-boundary with Int (4 bytes) starting at index 8
        // Index 8, 9 (Chunk 1) and 10, 11 (Chunk 2)
        stream.amendAtPos(8, dos -> dos.writeInt(0x12345678));
        
        // Amend cross-boundary with Long (8 bytes) starting at index 16
        // Index 16, 17, 18, 19 (Chunk 2) and 20, 21, 22, 23 (Chunk 3)
        // Let's write more data first.
        stream.write(new byte[10]); // Now we have 30 bytes (3 chunks)
        
        stream.amendAtPos(16, dos -> dos.writeLong(0x0102030405060708L));

        stream.close();

        List<ByteBuffer> chunks = new ArrayList<>();
        stream.readyChunks().forEach(chunks::add);

        assertEquals(3, chunks.size());

        // Verify Int amendment
        ByteBuffer c1 = chunks.get(0).duplicate();
        c1.position(8);
        assertEquals(0x12, c1.get());
        assertEquals(0x34, c1.get());
        
        ByteBuffer c2 = chunks.get(1).duplicate();
        assertEquals(0x56, c2.get());
        assertEquals(0x78, c2.get());
        
        // Verify Long amendment
        c2.position(c2.position() + 4); // index 16 in stream is index 6 in chunk 2 (10 + 2 read + 4 more)
        assertEquals(0x01, c2.get());
        assertEquals(0x02, c2.get());
        assertEquals(0x03, c2.get());
        assertEquals(0x04, c2.get());
        
        ByteBuffer c3 = chunks.get(2).duplicate();
        assertEquals(0x05, c3.get());
        assertEquals(0x06, c3.get());
        assertEquals(0x07, c3.get());
        assertEquals(0x08, c3.get());
    }

    @Test
    public void testMixedAmendingWrappedData() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        int chunkSize = 10;
        
        // Wrapper adds '[' and ']' in-place
        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> {
            int dataStart = buf.position();
            int dataEnd = buf.limit();
            buf.position(dataStart - 1);
            buf.put((byte) '[');
            buf.limit(dataEnd + 1);
            buf.position(dataEnd);
            buf.put((byte) ']');
            ByteBuffer wrapped = buf.duplicate();
            wrapped.position(dataStart - 1);
            wrapped.limit(dataEnd + 1);
            buf.limit(buf.capacity());
            buf.position(dataEnd + 2); // Gap for ']' and next '['
            return wrapped;
        };

        buffer.position(1);
        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);
        
        // Write 25 bytes -> 3 chunks
        // Chunk 1: [0-9] at buf indices 1-10. '[' at 0, ']' at 11. Next starts at 13.
        // Chunk 2: [10-19] at buf indices 13-22. '[' at 12, ']' at 23. Next starts at 25.
        // Chunk 3: [20-24] at buf indices 25-29. '[' at 24, ']' at 30.
        for (int i = 0; i < 25; i++) {
            stream.write(i);
        }
        
        // Amend mixed:
        // 1. Within chunk 1
        stream.amendAtPos(3, dos -> dos.write(99)); 
        
        // 2. Cross boundary chunk 1 and 2
        // We want to amend stream pos 9 and stream pos 10
        stream.amendAtPos(9, dos -> dos.writeShort(0x8889)); 
        
        stream.close();

        List<ByteBuffer> chunks = new ArrayList<>();
        stream.readyChunks().forEach(chunks::add);

        assertEquals(3, chunks.size());

        // Verify Chunk 1
        ByteBuffer c1 = chunks.get(0).duplicate();
        assertEquals((byte)'[', c1.get());
        assertEquals(0, c1.get());
        assertEquals(1, c1.get());
        assertEquals(2, c1.get());
        assertEquals(99, c1.get()); // amended at stream pos 3
        c1.position(10); // stream pos 9
        assertEquals((byte)0x88, c1.get());
        assertEquals((byte)']', c1.get());

        // Verify Chunk 2
        ByteBuffer c2 = chunks.get(1).duplicate();
        assertEquals((byte)'[', c2.get());
        assertEquals((byte)0x89, c2.get()); // amended at stream pos 10
        assertEquals(11, c2.get());
    }

    @Test
    public void testVaryingChunkSizes() throws IOException {
        int[] chunkSizes = {1, 3, 7, 16, 1024};
        for (int chunkSize : chunkSizes) {
            ByteBuffer buffer = ByteBuffer.allocate(2048);
            // 1-byte header '['
            BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> {
                int dataStart = buf.position();
                int dataEnd = buf.limit();
                buf.position(dataStart - 1);
                buf.put((byte) '[');
                ByteBuffer wrapped = buf.duplicate();
                wrapped.position(dataStart - 1);
                wrapped.limit(dataEnd);
                buf.limit(buf.capacity());
                buf.position(dataEnd + 1); // Skip 1 byte for next header
                return wrapped;
            };

            buffer.position(1); // Reserve first header
            ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);
            byte[] data = new byte[100];
            for (int i = 0; i < 100; i++) data[i] = (byte) i;
            stream.write(data);

            // Amend some data.
            // Data at logical index 10.
            // Absolute position = 1 (init) + chunk_idx * (chunkSize + 1) + 1 (header) + (offset_in_chunk)
            // If chunkSize = 3:
            // Chunk 0: pos 1-3. Total bytes 3.
            // Chunk 1: pos 5-7. Total bytes 6.
            // Chunk 2: pos 9-11. Total bytes 9.
            // Chunk 3: pos 13-15. Logical index 10 is at pos 14.
            
            int logicalIndex = 10;
            stream.amendAtPos(logicalIndex, dos -> dos.write(new byte[]{100, 101, 102}));

            stream.close();

            List<ByteBuffer> chunks = new ArrayList<>();
            stream.readyChunks().forEach(chunks::add);

            int totalBytes = 0;
            for (ByteBuffer chunk : chunks) {
                totalBytes += (chunk.remaining() - 1); // Exclude header
            }
            assertEquals(100, totalBytes);

            // Check amendment in payload
            assertEquals((byte)100, readByteAtLogical(chunks, 10));
            assertEquals((byte)101, readByteAtLogical(chunks, 11));
            assertEquals((byte)102, readByteAtLogical(chunks, 12));
        }
    }

    private byte readByteAtLogical(List<ByteBuffer> chunks, int logicalPos) {
        int currentLogical = 0;
        for (ByteBuffer chunk : chunks) {
            int payloadSize = chunk.remaining() - 1;
            if (logicalPos < currentLogical + payloadSize) {
                return chunk.get(chunk.position() + 1 + (logicalPos - currentLogical));
            }
            currentLogical += payloadSize;
        }
        throw new IndexOutOfBoundsException("Logical pos " + logicalPos + " out of bounds");
    }

    @Test
    public void testAmendmentOutsidePayload() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        int chunkSize = 10;
        // 1-byte header '['
        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> {
            int dataStart = buf.position();
            int dataEnd = buf.limit();
            buf.position(dataStart - 1);
            buf.put((byte) '[');
            ByteBuffer wrapped = buf.duplicate();
            wrapped.position(dataStart - 1);
            wrapped.limit(dataEnd);
            buf.limit(buf.capacity());
            buf.position(dataEnd + 1);
            return wrapped;
        };

        buffer.position(1);
        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);
        stream.write(new byte[20]); // Logical indices 0-19
        
        // Attempt to amend at logical position -1
        assertThrows(Exception.class, () -> {
            stream.amendAtPos(-1, dos -> dos.write(77));
        });

        // Attempt to amend at logical position 20 (not yet written)
        assertThrows(Exception.class, () -> {
            stream.amendAtPos(20, dos -> dos.write(88));
        });
    }

    @Test
    public void testAmendmentExactlyAtBoundaries() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        int chunkSize = 10;
        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> {
            ByteBuffer res = buf.duplicate();
            int limit = buf.limit();
            buf.limit(buf.capacity());
            buf.position(limit);
            return res;
        };

        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);
        stream.write(new byte[30]);

        // Amendment exactly at the end of first chunk (pos 9)
        stream.amendAtPos(9, dos -> dos.write(77));
        
        // Amendment exactly at the start of second chunk (pos 10)
        stream.amendAtPos(10, dos -> dos.write(88));
        
        stream.close();
        
        List<ByteBuffer> chunks = new ArrayList<>();
        stream.readyChunks().forEach(chunks::add);
        
        ByteBuffer c0 = chunks.get(0).duplicate();
        assertEquals(77, c0.get(c0.position() + 9), "Chunk 0 at index 9 should be 77");
        
        ByteBuffer c1 = chunks.get(1).duplicate();
        assertEquals(88, c1.get(c1.position()), "Chunk 1 at index 0 should be 88");
    }

    @Test
    public void testDifferentDataTypes() throws IOException {
        System.out.println("[DEBUG_LOG] Starting testDifferentDataTypes");
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        int chunkSize = 16;
        
        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> {
            ByteBuffer res = buf.duplicate();
            int limit = buf.limit();
            buf.limit(buf.capacity());
            buf.position(limit);
            return res;
        };

        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);
        
        stream.writeBoolean(true);     // 1 byte
        stream.writeByte(10);          // 1 byte
        stream.writeShort(1000);       // 2 bytes
        stream.writeInt(100000);       // 4 bytes
        stream.writeLong(10000000000L); // 8 bytes
        // Total 16 bytes - exactly one chunk
        
        stream.close();

        List<ByteBuffer> chunks = new ArrayList<>();
        stream.readyChunks().forEach(chunks::add);

        assertEquals(1, chunks.size());
        ByteBuffer c = chunks.get(0).duplicate();
        assertEquals(1, c.get());
        assertEquals(10, c.get());
        assertEquals(1000, c.getShort());
        assertEquals(100000, c.getInt());
        assertEquals(10000000000L, c.getLong());
    }

    @Test
    public void testReadyContentFrom() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        int chunkSize = 5;
        
        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> {
            // Add a gap of 2 bytes between chunks
            int nextStart = buf.limit() + 2;
            buf.limit(buf.capacity());
            buf.position(nextStart);
            return null; // we don't care about readyChunks here
        };

        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);
        
        // Write 12 bytes -> 3 chunks (5, 5, 2)
        // Positions:
        // Chunk 0: 0-4
        // Gap: 5-6
        // Chunk 1: 7-11
        // Gap: 12-13
        // Chunk 2: 14-15
        
        stream.write(new byte[]{1, 2, 3, 4, 5});
        int posAfterFirstChunk = stream.getPos(); // Should be 5
        stream.write(new byte[]{6, 7, 8, 9, 10});
        stream.write(new byte[]{11, 12});
        
        // Test readyContentFrom
        List<ByteBuffer> content = new ArrayList<>();
        stream.readyContentFrom(0).forEach(content::add);
        
        // Should have 3 buffers: [1,2,3,4,5], [6,7,8,9,10], [11,12]
        assertEquals(3, content.size());
        assertArrayEquals(new byte[]{1, 2, 3, 4, 5}, getBytes(content.get(0)));
        assertArrayEquals(new byte[]{6, 7, 8, 9, 10}, getBytes(content.get(1)));
        assertArrayEquals(new byte[]{11, 12}, getBytes(content.get(2)));
        
        // Test from middle
        content.clear();
        stream.readyContentFrom(posAfterFirstChunk).forEach(content::add);
        assertEquals(2, content.size());
        assertArrayEquals(new byte[]{6, 7, 8, 9, 10}, getBytes(content.get(0)));
        assertArrayEquals(new byte[]{11, 12}, getBytes(content.get(1)));
    }

    private byte[] getBytes(ByteBuffer buf) {
        byte[] bytes = new byte[buf.remaining()];
        buf.duplicate().get(bytes);
        return bytes;
    }
}
