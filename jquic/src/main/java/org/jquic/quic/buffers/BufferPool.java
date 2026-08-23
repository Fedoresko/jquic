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

public class BufferPool implements ReadBufferPool, WriteBufferPool, CryptoBufferPool {
    public static final int READ_BUFFER_SIZE = 2048;
    public static final int WRITE_BUFFER_SIZE = 2048;
    public static final int INITIAL_SIZE = 100;

    private final MpmcUnboundedXaddArrayQueue<RootPoolBuffer> readBufferPool = new MpmcUnboundedXaddArrayQueue<>( 10, 100);
    private final MpmcUnboundedXaddArrayQueue<RootPoolBuffer> writeBufferPool = new MpmcUnboundedXaddArrayQueue<>( 10, 100);
    private final MpmcUnboundedXaddArrayQueue<RootPoolBuffer> cryptoBufferPool = new MpmcUnboundedXaddArrayQueue<>( 10, 100);

    public BufferPool() {
        for (int i = 0; i < INITIAL_SIZE; i++) {
            readBufferPool.offer(new RootPoolBuffer(ByteBuffer.allocateDirect(READ_BUFFER_SIZE), readBufferPool));
            writeBufferPool.offer(new RootPoolBuffer(ByteBuffer.allocateDirect(WRITE_BUFFER_SIZE), writeBufferPool));
        }
    }

    public int readBufferSize() {
        return readBufferPool.size();
    }
    public int writeBufferSize() {
        return writeBufferPool.size();
    }

    @Override
    public PoolBuffer requestReadBuffer() {
        return requestBuffer(READ_BUFFER_SIZE, readBufferPool);
    }

    @Override
    public PoolBuffer requestWriteBuffer() {
        return requestBuffer(WRITE_BUFFER_SIZE, writeBufferPool);
    }

    @Override
    public PoolBuffer requestCryptoBuffer(int size) {
        return requestBuffer(size, cryptoBufferPool);
    }

    static void returnBuffer(RootPoolBuffer buffer, MpmcUnboundedXaddArrayQueue<RootPoolBuffer> queue) {
        queue.offer(buffer);
        if (queue.size() >= 150) {
            for (int i = 0; i < 50; i++) {
                queue.poll(); // Free excessive data
            }
        }
    }

    private static PoolBuffer requestBuffer(int size, MpmcUnboundedXaddArrayQueue<RootPoolBuffer> queue) {
        RootPoolBuffer buffer = queue.poll();
        if (buffer == null) {
            buffer = new RootPoolBuffer(ByteBuffer.allocateDirect(size + 200), queue);
        } else {
            buffer.buffer.clear();
        }

        buffer.buf().position(100);
        return buffer.borrow();
    }
}

