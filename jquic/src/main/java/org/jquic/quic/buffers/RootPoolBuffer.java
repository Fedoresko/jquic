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
import java.util.concurrent.atomic.AtomicInteger;

import static org.jquic.quic.buffers.BufferPool.returnBuffer;

public class RootPoolBuffer implements PoolBuffer {
    public final ByteBuffer buffer;
    private final MpmcUnboundedXaddArrayQueue<RootPoolBuffer> queue;
    AtomicInteger count = new AtomicInteger(0);

    public RootPoolBuffer(ByteBuffer buffer, MpmcUnboundedXaddArrayQueue<RootPoolBuffer> pool) {
        this.buffer = buffer;
        this.queue = pool;
    }

    @Override
    public PoolBuffer borrow() {
        count.incrementAndGet();
        return new BorrowedPoolBuffer(this, buffer.duplicate());
    }

    public void release() {
        int cnt = count.decrementAndGet();
        if (cnt == 0) {
            returnBuffer(this, queue);
        }
        if (cnt < 0) {
            throw new IllegalStateException();
        }
    }

    @Override
    public ByteBuffer buf() {
        return buffer;
    }
}

