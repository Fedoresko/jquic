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

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

/**
 * This class supports writing in a zero-copy buffer with splitting data in chunks
 * It works upon an underlying ByteBuffer pool able to allocate a large enough number of buffers to contain all final data.
 * Data is written using standard java.io.DataOutputStream methods.
 * It calls chunkWrapper callback, that could wrap chunk data with some user headers\trailers and adjust the buffer position
 * to the place of the next chunk.
 * It supports amendAtPos to update reserved placeholder in original data limited to size of current buffer.
 * Use pollReadyChunk() to collect all wrapped chunks with final data or set ChunkConsumer to consume chunks as soon as they appear.
 * Use readyContentFrom() to collect recently written data without wrapping but with all amendments applied
 * limited to size of current buffer.
 */
public abstract class ChunkedOutputStreamWithAmendments extends DataOutputStream implements BackwardReadBuffer {
    /**
     * Create new NonWrappingChunkedOutputStreamWithAmendments
     *
     * @param pool         - pool for underlying ByteBuffers.
     * @param chunkSize    - fixed size of chunk for written data to be split into
     * @param trailingPadding - reserved size between wrapped chunks on buffer (could be used for further wrapping)
     * @param chunkWrapper - callback that wraps a chunk with optional header\footer, returns the result as ButeBuffer,
     *                     and adjusts passed ByteBuffer position where to continue writes (reserve header space).
     */
    public static ChunkedOutputStreamWithAmendments createNonWrapping(WriteBufferPool pool, int chunkSize, int trailingPadding,
                                                                      ChunkWrapper chunkWrapper) {
        return new ChunkedOutputStreamWithAmendmentsImpl(pool, chunkSize, trailingPadding, chunkWrapper);
    }

    ChunkedOutputStreamWithAmendments(OutputStream out) {
        super(out);
    }

    public interface Writer {
        void write(DataOutputStream dos) throws IOException;
    }

    public interface ChunkWrapper {
        /**
         * Wrap created chunk with header\footer; wrapped buffers are passed to consumers,
         * leaving trailingPadding between
         * @param buf - current chunk boundaries
         * @param offset - logical offset (bytes written before chunk start)
         * @param isFinal - if stream was closed
         * @return return boundaries of wrapped chunk
         */
        ByteBuffer wrapBuffer(ByteBuffer buf, int offset, boolean isFinal);
    }

    public interface ChunkConsumer {
        /**
         * Get the next generated chunk
         * @param buf - borrowed link to underlying buffer with written chunk boundaries
         * @return size of nextChunk;
         */
        int accept(PoolBuffer buf) throws IOException;
    }

    /**
     * Set chunk consumer.
     * It is expected that pollReadyChunk would always return null if consumer is set.
     *
     * @param consumer called immediately to consume chunk when ready.
     */
    public abstract void setChunkConsumer(ChunkConsumer consumer);

    /**
     * Returns position for goBacks, readyContentFrom, and other...
     *
     * @return - current logical offset (number of bytes written).
     */
    public abstract int getPos();

    /**
     * Poll a borrowed link to ready and wrapped chunk.
     *
     * @return the first added chunk in queue, null if nothing left.
     */
    public abstract PoolBuffer pollReadyChunk();

    /**
     * Return if the stream was closed
     */
    public abstract boolean isClosed();

}

