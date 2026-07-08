package org.fmalyshev.quic.buffers;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.function.BiFunction;
import java.util.function.Consumer;

/**
 * This class supports writing in a zero-copy buffer with splitting data in chunks
 * It works upon an underlying ByteBuffer large enough to contain all final data.
 * Data is written using standard java.io.DataOutputStream methods.
 * It calls chunkWrapper callback, that could wrap chunk data with some user headers\trailers, and adjust buffer position to the start of the next chunk.
 * It supports amendAtPos to update reserved placeholder in original data.
 * <p>
 * After the Stream is closed, use pollReadyChunk() to collect all wrapped chunks with final data.
 * Use readyContentFrom() to collect recently written data without wrapping but with all amendments applied.
 */
public class ChunkedOutputStreamWithAmendmentsImpl extends ChunkedOutputStreamWithAmendments {
    private final ByteBuffer buffer;
    private final BiFunction<ByteBuffer, Integer, ByteBuffer> chunkWrapper;

    /**
     * Create new ChunkedOutputStreamWithAmendments
     *
     * @param buffer       - underlying ByteBuffer large enough to accommodate all wrapped chunks.
     * @param chunkSize    - fixed size of chunk for written data to be split into
     * @param chunkWrapper - callback that wraps a chunk with optional header\footer, returns the result as ButeBuffer,
     *                     and adjusts passed ByteBuffer position where to continue writes (reserve header space).
     */
    public ChunkedOutputStreamWithAmendmentsImpl(ByteBuffer buffer, int chunkSize,
                                                 BiFunction<ByteBuffer, Integer, ByteBuffer> chunkWrapper) {
        super(new ChunkingOutputStream(buffer, chunkSize));
        ((ChunkingOutputStream) out).setCallback(this::sendChunk);
        this.buffer = buffer;
        this.chunkWrapper = chunkWrapper;
    }

    private ByteBuffer sendChunk(ByteBuffer buffer, Integer offset) {
        return chunkWrapper.apply(buffer, offset);
    }

    @Override
    public void close() throws IOException {
        ((ChunkingOutputStream) out).flush();
        super.close();
    }

    @Override
    public void setChunkConsumer(Consumer<ByteBuffer> consumer) {
        ((ChunkingOutputStream) out).setChunkConsumer(consumer);
    }

    @Override
    public void amendAtPos(int position, Writer writer) throws IOException {
        ((ChunkingOutputStream) out).goBack(position);
        writer.write(this);
        ((ChunkingOutputStream) out).toPresent();
    }

    @Override
    public int getPos() {
        return ((ChunkingOutputStream) out).getPos();
    }

    @Override
    public ByteBuffer pollReadyChunk() {
        return ((ChunkingOutputStream) out).pollReadyChunk();
    }

    @Override
    public Iterable<ByteBuffer> readyContentFrom(int position) {
        return new Iterable<ByteBuffer>() {
            @Override
            public Iterator<ByteBuffer> iterator() {
                return ((ChunkingOutputStream) out).readyContentFrom(position);
            }
        };
    }
}
