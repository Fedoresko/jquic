package org.jquic.quic.buffers;

import java.io.IOException;
import java.nio.ByteBuffer;

public class ChunkedOutputStreamWithAmendmentsImpl extends ChunkedOutputStreamWithAmendments {
    private volatile boolean isClosed = false;

    public ChunkedOutputStreamWithAmendmentsImpl(BufferPool pool, int chunkSize, int trailingPadding,
                                                 ChunkWrapper chunkWrapper) {
        super(new ChunkingOutputStream(pool, chunkSize, trailingPadding));
        ((ChunkingOutputStream) out).setCallback(chunkWrapper);
    }

    @Override
    public void close() throws IOException {
        isClosed = true;
        out.close();
    }

    @Override
    public boolean isClosed() {
        return isClosed;
    }

    @Override
    public void flush() throws IOException {
        out.flush();
    }

    @Override
    public void setChunkConsumer(ChunkConsumer consumer) {
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
    public PoolBuffer pollReadyChunk() {
        return ((ChunkingOutputStream) out).pollReadyChunk();
    }

    @Override
    public PoolBuffer peekReadyChunk() {
        return ((ChunkingOutputStream) out).peekReadyChunk();
    }

    @Override
    public int bufferedBytes() {
        return 0;
    }

    @Override
    public Iterable<ByteBuffer> readyContentFrom(int position) {
        return () -> ((ChunkingOutputStream) out).readyContentFrom(position);
    }
}
