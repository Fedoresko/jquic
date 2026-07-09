package org.fmalyshev.quic.buffers;

import org.jctools.queues.MpmcUnboundedXaddArrayQueue;

import java.nio.ByteBuffer;

public class BufferPool {
    public static final int READ_BUFFER_SIZE = 2048;
    public static final int WRITE_BUFFER_SIZE = 2048;
    public static final int INITIAL_SIZE = 100;

    private final MpmcUnboundedXaddArrayQueue<RootPoolBuffer> readBufferPool = new MpmcUnboundedXaddArrayQueue<>(READ_BUFFER_SIZE * 10, 100);
    private final MpmcUnboundedXaddArrayQueue<RootPoolBuffer> writeBufferPool = new MpmcUnboundedXaddArrayQueue<>(WRITE_BUFFER_SIZE * 10, 100);

    public BufferPool() {
        for (int i = 0; i < INITIAL_SIZE; i++) {
            readBufferPool.offer(new RootPoolBuffer(ByteBuffer.allocateDirect(READ_BUFFER_SIZE), false));
            writeBufferPool.offer(new RootPoolBuffer(ByteBuffer.allocateDirect(WRITE_BUFFER_SIZE), true));
        }
    }

    public PoolBuffer requestReadBuffer() {
        RootPoolBuffer buffer = readBufferPool.poll();
        if (buffer == null) {
            buffer = new RootPoolBuffer(ByteBuffer.allocateDirect(READ_BUFFER_SIZE), false);
        } else {
            buffer.buffer.clear();
        }
        return buffer.borrow();
    }

    public PoolBuffer requestWriteBuffer() {
        RootPoolBuffer buffer = writeBufferPool.poll();
        if (buffer == null) {
            buffer = new RootPoolBuffer(ByteBuffer.allocateDirect(WRITE_BUFFER_SIZE), true);
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
