package org.jquic.quic.buffers;

import java.nio.ByteBuffer;

/**
 * This class represents a reference to Pooled Buffer.
 * It uses a reference counter to detect when Pooled Buffer is no longer needed and could be returned to the pool.
 * Use borrow() to derive a new reference preserving the current position and limit of ByteBuffer (e.g., for passing in submodule).
 * Use release then reference is no longer needed for read or write.
 */
public interface PoolBuffer {
    /**
     * Return a duplicate of underlying ByteBuffer (reference) and increase the reference counter.
     * @return derived reference to PoolBuffer
     */
    PoolBuffer borrow();

    /**
     * Mark that reference is no longer needed and the buffer could be returned to the pool.
     * Decreases reference counter.
     */
    void release();

    /**
     * Returns reference ByteBuffer to underlying Pool Buffer.
     * @return reference ButeBuffer or null after {@release()}
     */
    ByteBuffer buf();
}
