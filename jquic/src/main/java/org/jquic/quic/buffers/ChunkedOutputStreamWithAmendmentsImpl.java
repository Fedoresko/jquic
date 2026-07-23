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
package org.jquic.quic.buffers;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Iterator;

/**
 * This class supports writing in a zero-copy buffer with splitting data in chunks
 * It works upon an underlying ByteBuffer large enough to contain all final data.
 * Data is written using standard java.io.DataOutputStream methods.
 * It calls chunkWrapper callback, that could wrap chunk data with some user headers\trailers, and adjust buffer position to the lower of the next chunk.
 * It supports amendAtPos to update reserved placeholder in original data.
 * <p>
 * After the Stream is closed, use pollReadyChunk() to collect all wrapped chunks with final data.
 * Use readyContentFrom() to collect recently written data without wrapping but with all amendments applied.
 */
public class ChunkedOutputStreamWithAmendmentsImpl extends ChunkedOutputStreamWithAmendments {
    private volatile boolean isClosed = false;
    /**
     * Create new ChunkedOutputStreamWithAmendments
     *
     * @param pool         - pool for underlying ByteBuffers.
     * @param chunkSize    - fixed size of chunk for written data to be split into
     * @param chunkWrapper - callback that wraps a chunk with optional header\footer, returns the result as ButeBuffer,
     *                     and adjusts passed ByteBuffer position where to continue writes (reserve header space).
     */
    public ChunkedOutputStreamWithAmendmentsImpl(BufferPool pool, int chunkSize, int trailingPadding,
                                                 ChunkWrapper chunkWrapper) {
        super(new ChunkingOutputStream(pool, chunkSize, trailingPadding));
        ((ChunkingOutputStream) out).setCallback(chunkWrapper);
    }

    @Override
    public void close() throws IOException {
        super.close();
        isClosed = true;
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
        return ((ChunkingOutputStream) out).bufferedBytes();
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

