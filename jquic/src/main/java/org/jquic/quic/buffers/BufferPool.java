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

import org.jctools.queues.MpmcUnboundedXaddArrayQueue;

import java.nio.ByteBuffer;

public class BufferPool {
    public static final int READ_BUFFER_SIZE = 2048;
    public static final int WRITE_BUFFER_SIZE = 4096;
    public static final int INITIAL_SIZE = 100;

    private final MpmcUnboundedXaddArrayQueue<RootPoolBuffer> readBufferPool = new MpmcUnboundedXaddArrayQueue<>(READ_BUFFER_SIZE * 10, 100);
    private final MpmcUnboundedXaddArrayQueue<RootPoolBuffer> writeBufferPool = new MpmcUnboundedXaddArrayQueue<>(WRITE_BUFFER_SIZE * 10, 100);

    public BufferPool() {
        for (int i = 0; i < INITIAL_SIZE; i++) {
            readBufferPool.offer(new RootPoolBuffer(ByteBuffer.allocateDirect(READ_BUFFER_SIZE), this, false));
            writeBufferPool.offer(new RootPoolBuffer(ByteBuffer.allocateDirect(WRITE_BUFFER_SIZE), this, true));
        }
    }

    public PoolBuffer requestReadBuffer() {
        RootPoolBuffer buffer = readBufferPool.poll();
        if (buffer == null) {
            buffer = new RootPoolBuffer(ByteBuffer.allocateDirect(READ_BUFFER_SIZE), this,false);
        } else {
            buffer.buffer.clear();
        }
        return buffer.borrow();
    }

    public PoolBuffer requestWriteBuffer() {
        RootPoolBuffer buffer = writeBufferPool.poll();
        if (buffer == null) {
            buffer = new RootPoolBuffer(ByteBuffer.allocateDirect(WRITE_BUFFER_SIZE), this, true);
        } else {
            buffer.buffer.clear();
        }

        buffer.buf().position(100);
        return buffer.borrow();
    }

    void returnReadBuffer(RootPoolBuffer buffer) {
        readBufferPool.offer(buffer);
    }

    void returnWriteBuffer(RootPoolBuffer buffer) {
        writeBufferPool.offer(buffer);
    }
}

