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
    public Iterable<ByteBuffer> readyContentFrom(int position) {
        return () -> ((ChunkingOutputStream) out).readyContentFrom(position);
    }
}
