package org.jquic.quic.buffers;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class SlicingOutputStreamTest {

    static class TestPoolBuffer implements PoolBuffer {
        private final ByteBuffer buffer;

        TestPoolBuffer(ByteBuffer buffer) {
            this.buffer = buffer;
        }

        @Override
        public PoolBuffer borrow() {
            return this;
        }

        @Override
        public void release() {
        }

        @Override
        public ByteBuffer buf() {
            return buffer;
        }
    }

    @Test
    public void testComplexSlicing() throws IOException {
        ByteBuffer raw = ByteBuffer.allocate(100);
        TestPoolBuffer pbuf = new TestPoolBuffer(raw);
        List<byte[]> consumedChunks = new ArrayList<>();

        ChunkedOutputStreamWithAmendments.ChunkConsumer consumer = (pb) -> {
            ByteBuffer b = pb.buf();
            byte[] data = new byte[b.remaining()];
            b.get(data);
            consumedChunks.add(data);
            pb.release();
            return 10; // next chunk size
        };

        // chunkSize=10, trailingPadding=5
        SlicingOutputStream out = new SlicingOutputStream(pbuf, 10, 5, consumer);

        // Write 10 bytes -> should trigger callback
        byte[] data1 = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        out.write(data1);

        assertEquals(1, consumedChunks.size());
        assertArrayEquals(data1, consumedChunks.get(0));
        assertEquals(10, out.getPos());

        // Logical offset is 10. Gap of 5 was added.
        // Current position in raw buffer should be 10 + 5 = 15.
        assertEquals(out.firstChunkStart() + 15, raw.position());

        // Write 5 more bytes
        byte[] data2 = new byte[]{10, 11, 12, 13, 14};
        out.write(data2);
        assertEquals(15, out.getPos());
        assertEquals(out.firstChunkStart() + 20, raw.position());

        // Test goBack and amendment
        // Go back to logical position 5 (middle of data1)
        out.goBack(5);
        out.write((byte) 99);
        out.toPresent();

        // Verify amendment via readyContentFrom
        Iterator<ByteBuffer> it = out.readyContentFrom(0);
        assertTrue(it.hasNext());
        ByteBuffer chunk1 = it.next();
        assertEquals(10, chunk1.remaining());
        assertEquals((byte) 99, chunk1.get(chunk1.position() + 5));

        assertTrue(it.hasNext());
        ByteBuffer chunk2 = it.next();
        assertEquals(5, chunk2.remaining());
        byte[] readData2 = new byte[5];
        chunk2.get(readData2);
        assertArrayEquals(data2, readData2);

        assertFalse(it.hasNext());

        // Test multi-chunk write
        byte[] data3 = new byte[15]; // Should trigger callback twice (once at 10, then leave 5 in current)
        for (int i = 0; i < 15; i++) data3[i] = (byte) (20 + i);
        out.write(data3);

        // consumedChunks should have 2 chunks now: data1 and first 10 bytes of data3 (data2 is not consumed yet)
        // Wait, data2 was 5 bytes, then we wrote 15 bytes. 
        // Total logical: 10 (data1) + 5 (data2) + 15 (data3) = 30.
        // Chunk boundaries: 
        // 0-10 (consumed)
        // 10-20 (consumed) - data2(5) + data3_part1(5) = 10.
        // 20-30 (not consumed yet) - data3_part2(10) -> wait, if chunk size is 10, this should be consumed.

        assertEquals(3, consumedChunks.size());

        out.flush();
        assertEquals(3, consumedChunks.size());

        // Check last chunk
        assertArrayEquals(new byte[]{25, 26, 27, 28, 29, 30, 31, 32, 33, 34}, consumedChunks.get(2));
    }

    @Test
    public void testReadyContentFromVariousPositions() throws IOException {
        ByteBuffer raw = ByteBuffer.allocate(200);
        TestPoolBuffer pbuf = new TestPoolBuffer(raw);

        ChunkedOutputStreamWithAmendments.ChunkConsumer consumer = (pb) -> {
            pb.release();
            return 10;
        };

        SlicingOutputStream out = new SlicingOutputStream(pbuf, 10, 2, consumer);
        // Logical: 0-10 (raw 0-10), gap 2
        // Logical: 10-20 (raw 12-22), gap 2
        // Logical: 20-30 (raw 24-34), gap 2
        // Logical: 30-35 (raw 36-41)
        out.write(new byte[35]);

        // At pos 0: 3 chunks (10, 10, 10) + current (5)
        Iterator<ByteBuffer> it = out.readyContentFrom(0);
        assertEquals(10, it.next().remaining());
        assertEquals(10, it.next().remaining());
        assertEquals(10, it.next().remaining());
        assertEquals(5, it.next().remaining());
        assertFalse(it.hasNext());

        // At pos 5: 1st chunk (5 remaining), then 10, 10, 5
        it = out.readyContentFrom(5);
        assertEquals(5, it.next().remaining());
        assertEquals(10, it.next().remaining());
        assertEquals(10, it.next().remaining());
        assertEquals(5, it.next().remaining());
        assertFalse(it.hasNext());

        // At pos 10: 2nd chunk (10), 3rd (10), current (5)
        it = out.readyContentFrom(10);
        assertEquals(10, it.next().remaining());
        assertEquals(10, it.next().remaining());
        assertEquals(5, it.next().remaining());
        assertFalse(it.hasNext());

        // At pos 15: 2nd chunk (5), 3rd (10), current (5)
        it = out.readyContentFrom(15);
        assertEquals(5, it.next().remaining());
        assertEquals(10, it.next().remaining());
        assertEquals(5, it.next().remaining());
        assertFalse(it.hasNext());

        // At pos 25: 3rd chunk (5), current (5)
        it = out.readyContentFrom(25);
        assertEquals(5, it.next().remaining());
        assertEquals(5, it.next().remaining());
        assertFalse(it.hasNext());

        // At pos 32: current (2) -> wait, it is at 30..35. 32 to 35 is 3 bytes.
        it = out.readyContentFrom(32);
        assertEquals(3, it.next().remaining());
        assertFalse(it.hasNext());
    }

    @Test
    public void testVaryingChunkSizes() throws IOException {
        ByteBuffer raw = ByteBuffer.allocate(200);
        TestPoolBuffer pbuf = new TestPoolBuffer(raw);
        List<Integer> acceptedSizes = new ArrayList<>();

        ChunkedOutputStreamWithAmendments.ChunkConsumer consumer = (pb) -> {
            int size = pb.buf().remaining();
            acceptedSizes.add(size);
            pb.release();
            // Return varying next chunk sizes
            if (size == 10) return 20;
            if (size == 20) return 5;
            return 10;
        };

        SlicingOutputStream out = new SlicingOutputStream(pbuf, 10, 0, consumer);

        // Write 10 bytes -> triggers callback (size 10), nextChunkSize becomes 20
        out.write(new byte[10]);
        assertEquals(1, acceptedSizes.size());
        assertEquals(10, acceptedSizes.get(0));

        // Write 15 bytes -> no trigger (needs 20)
        out.write(new byte[15]);
        assertEquals(1, acceptedSizes.size());

        // Write 5 more bytes -> triggers callback (size 20), nextChunkSize becomes 5
        out.write(new byte[5]);
        assertEquals(2, acceptedSizes.size());
        assertEquals(20, acceptedSizes.get(1));

        // Write 5 bytes -> triggers callback (size 5), nextChunkSize becomes 10
        out.write(new byte[5]);
        assertEquals(3, acceptedSizes.size());
        assertEquals(5, acceptedSizes.get(2));

        // Write 15 bytes -> triggers callback (size 10), then leaves 5
        out.write(new byte[15]);
        assertEquals(4, acceptedSizes.size());
        assertEquals(10, acceptedSizes.get(3));

        assertEquals(10 + 20 + 5 + 10 + 5, out.getPos());
    }

    @Test
    public void testReadyContentFromWithGaps() throws IOException {
        ByteBuffer raw = ByteBuffer.allocate(100);
        TestPoolBuffer pbuf = new TestPoolBuffer(raw);

        ChunkedOutputStreamWithAmendments.ChunkConsumer consumer = (pb) -> {
            pb.release();
            return 10;
        };

        SlicingOutputStream out = new SlicingOutputStream(pbuf, 10, 2, consumer);
        out.write(new byte[10]); // logical 0-10, raw 0-10. Callback -> gap 10-12.
        out.write(new byte[10]); // logical 10-20, raw 12-22. Callback -> gap 22-24.
        out.write(new byte[5]);  // logical 20-25, raw 24-29.

        Iterator<ByteBuffer> it = out.readyContentFrom(5);
        // Should return 5 bytes from first chunk, then 10 bytes from second, then 5 bytes from third.
        assertTrue(it.hasNext());
        assertEquals(5, it.next().remaining());
        assertTrue(it.hasNext());
        assertEquals(10, it.next().remaining());
        assertTrue(it.hasNext());
        assertEquals(5, it.next().remaining());
        assertFalse(it.hasNext());
    }
}
