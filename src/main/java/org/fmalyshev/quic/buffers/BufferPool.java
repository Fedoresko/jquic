package org.fmalyshev.quic.buffers;

import org.jctools.queues.MpmcUnboundedXaddArrayQueue;

import java.nio.ByteBuffer;

public class BufferPool {
    public static final int BUFFER_SIZE = 4096;
    public static final int INITIAL_SIZE = 100;

    private final MpmcUnboundedXaddArrayQueue<RootPoolBuffer> readBufferPool = new MpmcUnboundedXaddArrayQueue<>(BUFFER_SIZE * 10, 100);

    public BufferPool() {
        for (int i = 0; i < INITIAL_SIZE; i++) {
            readBufferPool.offer(new RootPoolBuffer(ByteBuffer.allocateDirect(BUFFER_SIZE)));
        }
    }

    public PoolBuffer requestReadBuffer() {
        RootPoolBuffer buffer = readBufferPool.poll();
        if (buffer == null) {
            buffer = new RootPoolBuffer(ByteBuffer.allocateDirect(BUFFER_SIZE));
        } else {
            buffer.buffer.clear();
        }
        return buffer.borrow();
    }

    void returnReadBuffer(RootPoolBuffer buffer) {
        readBufferPool.offer(buffer);
    }
}
