package org.jquic.quic.buffers;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;

public class RootPoolBuffer implements PoolBuffer {
    public final ByteBuffer buffer;
    private final BufferPool pool;
    AtomicInteger count = new AtomicInteger(0);
    private final boolean writeBuffer;

    public RootPoolBuffer(ByteBuffer buffer, BufferPool pool, boolean writeBuffer) {
        this.buffer = buffer;
        this.pool = pool;
        this.writeBuffer = writeBuffer;
    }

    @Override
    public PoolBuffer borrow() {
        count.incrementAndGet();
        return new BorrowedPoolBuffer(this, buffer.duplicate());
    }

    public void release() {
        int cnt = count.decrementAndGet();
        if (cnt == 0) {
            if (writeBuffer) {
                pool.returnWriteBuffer(this);
            } else {
                pool.returnReadBuffer(this);
            }
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
