package org.fmalyshev.quic.buffers;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
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
        ByteBuffer polled;
        while ((polled = stream.pollReadyChunk()) != null) {
            chunks.add(polled);
        }

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
        ByteBuffer polled;
        while ((polled = stream.pollReadyChunk()) != null) {
            chunks.add(polled);
        }

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
        stream.amendAtPos(9, dos -> dos.write(new byte[]{1, 2})); // Writes to index 9 (higher of chunk 1) and 10 (lower of chunk 2)

        stream.close();

        List<ByteBuffer> chunks = new ArrayList<>();
        ByteBuffer polled;
        while ((polled = stream.pollReadyChunk()) != null) {
            chunks.add(polled);
        }

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
        ByteBuffer polled;
        while ((polled = stream.pollReadyChunk()) != null) {
            chunks.add(polled);
        }

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
        ByteBuffer polled;
        while ((polled = stream.pollReadyChunk()) != null) {
            chunks.add(polled);
        }

        assertEquals(3, chunks.size());

        // Verify Chunk 1
        ByteBuffer c1 = chunks.get(0).duplicate();
        assertEquals((byte) '[', c1.get());
        assertEquals(0, c1.get());
        assertEquals(1, c1.get());
        assertEquals(2, c1.get());
        assertEquals(99, c1.get()); // amended at stream pos 3
        c1.position(10); // stream pos 9
        assertEquals((byte) 0x88, c1.get());
        assertEquals((byte) ']', c1.get());

        // Verify Chunk 2
        ByteBuffer c2 = chunks.get(1).duplicate();
        assertEquals((byte) '[', c2.get());
        assertEquals((byte) 0x89, c2.get()); // amended at stream pos 10
        assertEquals(11, c2.get());
    }

    @Test
    public void testVaryingChunkSizes() throws IOException {
        int[] chunkSizes = {1, 3, 7, 16, 1024};
        for (int chunkSize : chunkSizes) {
            System.out.println(chunkSize);
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
            ByteBuffer polled;
            while ((polled = stream.pollReadyChunk()) != null) {
                chunks.add(polled);
            }

            int totalBytes = 0;
            for (ByteBuffer chunk : chunks) {
                totalBytes += (chunk.remaining() - 1); // Exc lude header
            }
            assertEquals(100, totalBytes);

            // Check amendment in payload
            assertEquals((byte) 100, readByteAtLogical(chunks, 10));
            assertEquals((byte) 101, readByteAtLogical(chunks, 11));
            assertEquals((byte) 102, readByteAtLogical(chunks, 12));
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

        // Amendment exactly at the higher of first chunk (pos 9)
        stream.amendAtPos(9, dos -> dos.write(77));

        // Amendment exactly at the lower of second chunk (pos 10)
        stream.amendAtPos(10, dos -> dos.write(88));

        stream.close();

        List<ByteBuffer> chunks = new ArrayList<>();
        ByteBuffer polled;
        while ((polled = stream.pollReadyChunk()) != null) {
            chunks.add(polled);
        }

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
        ByteBuffer polled;
        while ((polled = stream.pollReadyChunk()) != null) {
            chunks.add(polled);
        }

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
            return buf.limit(buf.limit() + 2); // we don't care about polled chunks here
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

    @Test
    public void testReadyContentFromWithWrapAround() throws IOException {
        int bufferSize = 20;
        int chunkSize = 10;
        ByteBuffer buffer = ByteBuffer.allocate(bufferSize);

        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> buf.duplicate();

        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);

        // Write 20 bytes -> 2 chunks of 10. Buffer is full.
        stream.write(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9});
        stream.write(new byte[]{10, 11, 12, 13, 14, 15, 16, 17, 18, 19});

        // Write 5 more bytes -> will wrap around in physical buffer
        stream.write(new byte[]{20, 21, 22, 23, 24});

        // Now logical content is:
        // 0-9: Chunk 0
        // 10-19: Chunk 1
        // 20-24: partial Chunk 2

        // Test readyContentFrom(10) - should return chunk 1 and partial chunk 2
        List<ByteBuffer> content = new ArrayList<>();
        stream.readyContentFrom(10).forEach(content::add);

        assertEquals(2, content.size());
        assertArrayEquals(new byte[]{10, 11, 12, 13, 14, 15, 16, 17, 18, 19}, getBytes(content.get(0)));
        assertArrayEquals(new byte[]{20, 21, 22, 23, 24}, getBytes(content.get(1)));
    }

    @Test
    public void testCircularBufferWrapAroundFailing() throws IOException {
        // Small buffer to force wrap-around quickly
        ByteBuffer buffer = ByteBuffer.allocate(16);
        int chunkSize = 10;

        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> buf.duplicate();

        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);

        // Write 15 bytes. buffer.position() = 15, remaining = 1. logicalOffset = 15.
        stream.write(new byte[15]);

        // Write 5 more bytes. 
        // Current implementation:
        // 1st byte: written at pos 15. buffer.position() = 16. remaining = 0.
        // buf.position(0) is called.
        // 2nd-5th bytes: written at pos 0-3. buffer.position() = 4.
        // Chunk 0 is logical 0-9. Chunk 1 is logical 10-19.
        // On logical 20, triggerCallback called.
        // It checks if Chunk 0 was consumed. It was not. 
        // It throws IllegalStateException: Buffer is full
        assertThrows(IllegalStateException.class, () -> stream.write(new byte[]{15, 16, 17, 18, 19}));
    }

    @Test
    public void testReadyContentFromAcrossPhysicalWrapAround() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(16);
        int chunkSize = 10;
        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> buf.duplicate();
        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);

        // Consume chunks to avoid Buffer Full exception
        List<ByteBuffer> consumedChunks = new ArrayList<>();
        stream.setChunkConsumer(consumedChunks::add);

        stream.write(new byte[15]);
        // buffer.position(0) will be called after next byte
        stream.write(new byte[]{15, 16, 17, 18, 19});

        // logical 10-19 spans across wrap around: buf 10-15 and buf 0-3

        List<ByteBuffer> content = new ArrayList<>();
        stream.readyContentFrom(10).forEach(content::add);

        // Expected: {0,0,0,0,0, 15, 16, 17, 18, 19}
        // Since it's split across physical boundary, it should return two buffers: buf[10-15] and buf[0-3]
        byte[] total = new byte[10];
        int offset = 0;
        for (ByteBuffer b : content) {
            int len = b.remaining();
            b.get(total, offset, len);
            offset += len;
        }

        // Logical indices:
        // 0-9: Chunk 0 (buf 0-9) - zeros
        // 10-14: buf 10-14 (part of Chunk 1) - zeros
        // 15: buf 15 (part of Chunk 1) - value 15
        // 16-19: buf 0-3 (part of Chunk 1) - values 16-19
        assertArrayEquals(new byte[]{0, 0, 0, 0, 0, 15, 16, 17, 18, 19}, total);
    }

    @Test
    public void testAmendAtPosAcrossPhysicalWrapAround() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(16);
        int chunkSize = 10;

        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> buf.duplicate();

        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);

        // Consume chunks to avoid Buffer Full exception
        List<ByteBuffer> consumedChunks = new ArrayList<>();
        stream.setChunkConsumer(consumedChunks::add);

        // Write 15 bytes
        stream.write(new byte[15]);

        // Write 5 more bytes (causes wrap around at physical pos 16)
        stream.write(new byte[]{15, 16, 17, 18, 19});

        // Logical positions: 
        // 14: buf[14]
        // 15: buf[15]
        // 16: buf[0]
        // 17: buf[1]

        // Amend at logical pos 14
        stream.amendAtPos(14, dos -> dos.write(new byte[]{88, 89, 90, 91}));

        stream.close();

        // Expected changes:
        // Logical pos 14: 2nd chunk, index 4 (14 - 10)
        // Logical pos 15: 2nd chunk, index 5
        // Logical pos 16: 2nd chunk, index 6
        // Logical pos 17: 2nd chunk, index 7

        ByteBuffer c2 = consumedChunks.get(1).duplicate();
        assertEquals((byte) 88, c2.get(c2.position() + 4));
        assertEquals((byte) 89, c2.get(c2.position() + 5));
        assertEquals((byte) 90, c2.get(c2.position() + 6));
        assertEquals((byte) 91, c2.get(c2.position() + 7));
    }

    @Test
    public void testWrapAroundWithVaryingWrapAdvance() throws IOException {
        // Test case where wrapper adds headers that cause physical position to advance beyond chunkSize
        ByteBuffer buffer = ByteBuffer.allocate(64);
        int chunkSize = 10;

        // Wrapper adds a 5-byte header before each chunk
        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> {
            int dataStart = buf.position();
            int dataEnd = buf.limit();

            // "Write" header before data
            buf.put(dataStart - 5, new byte[]{1, 2, 3, 4, 5});

            ByteBuffer wrapped = buf.duplicate();
            wrapped.position(dataStart - 5);
            wrapped.limit(dataEnd);

            // NOTE: buf.position() is NOT adjusted here. 
            // The system predicts advance as wrapped.remaining() - unwrapped.remaining()
            return wrapped;
        };

        buffer.position(5); // Initial header space
        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);

        List<byte[]> consumed = new ArrayList<>();
        stream.setChunkConsumer(buf -> {
            byte[] data = new byte[buf.remaining()];
            buf.get(data);
            consumed.add(data);
        });

        // Write 50 bytes -> 5 chunks
        // Each chunk takes 10 bytes of data.
        // wrapped chunk takes 15 bytes (10 data + 5 header).
        // advance = 15 - 10 = 5.
        // Total physical advance per chunk = 10 + 5 = 15.
        // 5 * 15 = 75 bytes. Buffer is 64. Will definitely wrap.
        for (int i = 0; i < 50; i++) {
            stream.write(i);
        }
        stream.close();

        assertEquals(5, consumed.size());

        // Verify data continuity despite wrap arounds and header jumps
        int expectedByte = 0;
        for (byte[] chunkData : consumed) {
            assertEquals(15, chunkData.length);
            byte[] header = Arrays.copyOfRange(chunkData, 0, 5);
            assertArrayEquals(new byte[]{1, 2, 3, 4, 5}, header);

            for (int i = 5; i < 15; i++) {
                assertEquals((byte) expectedByte++, chunkData[i]);
            }
        }
    }

    @Test
    public void testWrapAroundWithExtraTrailer() throws IOException {
        // Test case where wrapper adds headers AND trailers
        ByteBuffer buffer = ByteBuffer.allocate(64);
        int chunkSize = 10;

        // Wrapper adds a 2-byte header '[' and 2-byte trailer ']'
        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> {
            int dataStart = buf.position();
            int dataEnd = buf.limit();

            ByteBuffer wrapped = buf.duplicate();
            wrapped.position(dataStart - 2);
            wrapped.limit(dataEnd + 2);

            // Put data into the wrapped buffer slice
            wrapped.put(dataStart - 2, (byte) '<');
            wrapped.put(dataStart - 1, (byte) '<');
            wrapped.put(dataEnd, (byte) '>');
            wrapped.put(dataEnd + 1, (byte) '>');

            return wrapped;
        };

        buffer.position(2);
        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);

        List<byte[]> consumed = new ArrayList<>();
        stream.setChunkConsumer(buf -> {
            byte[] data = new byte[buf.remaining()];
            buf.get(data);
            consumed.add(data);
        });

        // Write 40 bytes -> 4 chunks
        // Each chunk: 10 data. 
        // Wrapped: 14 bytes (2 header + 10 data + 2 trailer).
        // advance = 14 - 10 = 4.
        // Physical footprint = 10 + 4 = 14.
        // 4 * 14 = 56. Buffer is 64. No wrap yet.
        // Let's write 50 bytes -> 5 chunks. 5 * 14 = 70. Will wrap.
        stream.write(new byte[50]);
        stream.close();

        assertEquals(5, consumed.size());
        for (int j = 0; j < consumed.size(); j++) {
            byte[] chunkData = consumed.get(j);
            assertEquals(14, chunkData.length, "Chunk " + j + " length mismatch");
            assertEquals((byte) '<', chunkData[0], "Chunk " + j + " header mismatch at 0");
            assertEquals((byte) '<', chunkData[1], "Chunk " + j + " header mismatch at 1");
            assertEquals((byte) '>', chunkData[12], "Chunk " + j + " trailer mismatch at 12");
            assertEquals((byte) '>', chunkData[13], "Chunk " + j + " trailer mismatch at 13");
        }
    }

    @Test
    public void testReadyContentFromWithMultipleWrapArounds() throws IOException {
        // Test readyContentFrom when data spans more than one physical wrap around
        ByteBuffer buffer = ByteBuffer.allocate(16);
        int chunkSize = 4; // Small chunks

        BiFunction<ByteBuffer, Integer, ByteBuffer> wrapper = (buf, offset) -> buf.duplicate();
        ChunkedOutputStreamWithAmendmentsImpl stream = new ChunkedOutputStreamWithAmendmentsImpl(buffer, chunkSize, wrapper);

        List<byte[]> consumed = new ArrayList<>();
        stream.setChunkConsumer(buf -> {
            byte[] data = new byte[buf.remaining()];
            buf.get(data);
            consumed.add(data);
        });

        // Write 28 bytes. 28 / 4 = 7 chunks.
        // Buffer size 16. 28 bytes will wrap around 28 / 16 = 1.75 times.
        // But we must NOT exceed capacity (16 bytes) in terms of unconsumed data.
        // wait, setChunkConsumer DOES consume data, so it should be fine?
        // Actually, triggerCallback calls consumer, but readyContentFrom 
        // retrieves data from the buffer. If it's overwritten, it's gone.
        // ChunkingOutputStream.goBack(0) would fail if logical 0 is more than capacity away.
        // So we can only write up to 16 bytes if we want to retrieve from logical 0.

        byte[] data = new byte[14];
        for (int i = 0; i < 14; i++) data[i] = (byte) i;
        stream.write(data);

        List<ByteBuffer> content = new ArrayList<>();
        stream.readyContentFrom(0).forEach(content::add);

        int totalLen = 0;
        for (ByteBuffer b : content) totalLen += b.remaining();
        assertEquals(14, totalLen);

        byte[] result = new byte[14];
        int off = 0;
        for (ByteBuffer b : content) {
            int len = b.remaining();
            b.get(result, off, len);
            off += len;
        }
        assertArrayEquals(data, result);

        // Now write more and check from a later position
        stream.write(new byte[]{14, 15, 16, 17, 18, 19}); // Total 20 bytes written.
        // Logical 0 is now 20 - 0 = 20 > 16. It should be unretrievable.
        // Logical 4 should still be retrievable? 20 - 4 = 16.

        content.clear();
        stream.readyContentFrom(4).forEach(content::add);
        totalLen = 0;
        for (ByteBuffer b : content) totalLen += b.remaining();
        assertEquals(16, totalLen);

        byte[] expectedPart = new byte[16];
        for (int i = 0; i < 16; i++) expectedPart[i] = (byte) (i + 4);

        result = new byte[16];
        off = 0;
        for (ByteBuffer b : content) {
            int len = b.remaining();
            b.get(result, off, len);
            off += len;
        }
        assertArrayEquals(expectedPart, result);
    }

    private byte[] getBytes(ByteBuffer buf) {
        byte[] bytes = new byte[buf.remaining()];
        buf.duplicate().get(bytes);
        return bytes;
    }
}
