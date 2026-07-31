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

import java.nio.ByteBuffer;

public class BorrowedPoolBuffer implements PoolBuffer {
    private final RootPoolBuffer rootPoolBuffer;
    private volatile ByteBuffer buffer;

    public BorrowedPoolBuffer(RootPoolBuffer rootPoolBuffer, ByteBuffer buffer) {
        this.rootPoolBuffer = rootPoolBuffer;
        this.buffer = buffer;
    }

    @Override
    public PoolBuffer borrow() {
        rootPoolBuffer.count.incrementAndGet();
        return new BorrowedPoolBuffer(rootPoolBuffer, buffer.duplicate());
    }

    @Override
    public void release() {
        if (buffer != null) {
            rootPoolBuffer.release();
        }
        buffer = null;
    }

    @Override
    public ByteBuffer buf() {
        return buffer;
    }
}

