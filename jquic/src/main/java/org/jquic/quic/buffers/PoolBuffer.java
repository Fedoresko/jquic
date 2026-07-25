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
     * @return reference ButeBuffer or null after
     */
    ByteBuffer buf();
}

