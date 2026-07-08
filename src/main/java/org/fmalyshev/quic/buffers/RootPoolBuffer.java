package org.fmalyshev.quic.buffers;

import org.fmalyshev.quic.QuicEngine;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;

public class RootPoolBuffer implements PoolBuffer {
    public final ByteBuffer buffer;
    AtomicInteger count = new AtomicInteger(0);
    private final boolean writeBuffer;

    public RootPoolBuffer(ByteBuffer buffer, boolean writeBuffer) {
        this.buffer = buffer;
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
                QuicEngine.getPool().returnWriteBuffer(this);
            } else {
                QuicEngine.getPool().returnReadBuffer(this);
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
