package org.fmalyshev.quic.buffers;

import java.nio.ByteBuffer;

public class BorrowedPoolBuffer implements PoolBuffer {
    private final RootPoolBuffer rootPoolBuffer;
    ByteBuffer buffer;

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
        rootPoolBuffer.release();
        buffer = null;
    }

    @Override
    public ByteBuffer buf() {
        return buffer;
    }
}
