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
package org.jquic.quic.streamapi.impl;

import org.jquic.quic.QuicException;
import org.jquic.quic.QuicTransportError;
import org.jquic.quic.buffers.PoolBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.WritableByteChannel;
import java.util.Map;
import java.util.TreeMap;

/**
 * Buffers incoming and outgoing data for a single QUIC stream.
 * Handles out-of-order frame arrival and reassembly.
 * Thread-safety: ALL methods are called from worker thread only - no synchronization needed.
 */
public class StreamBuffer {
    private static final Logger log = LoggerFactory.getLogger(StreamBuffer.class);
    private final long streamId;
    private final int streamBufferCapacity;

    // Incoming data buffer for reassembly (offset -> data)
    private final TreeMap<Long, PoolBuffer> incomingFragments = new TreeMap<>();
    private long nextExpectedOffset = 0;
    private boolean receivedFin = false;
    private long finOffset = -1;

    // Flow control tracking
    private long bufferedBytes = 0; // Bytes buffered but not yet delivered to application

    public StreamBuffer(long streamId, int streamBufferCapacity) {
        this.streamId = streamId;
        this.streamBufferCapacity = streamBufferCapacity;
    }

    public void free() {
        for (PoolBuffer poolBuffer : incomingFragments.values()) {
            poolBuffer.release();
        }
        incomingFragments.clear();
        bufferedBytes = 0;
    }

    /**
     * Adds incoming STREAM data to reassembly buffer.
     * Called by worker thread after processing STREAM frame event.
     *
     * @param offset Byte offset in the stream
     * @param data Frame data
     * @param fin Whether this frame has the FIN flag
     * @return true if this frame allows reading more data (in-order data received)
     */
    public boolean addIncomingData(long offset, PoolBuffer data, boolean fin) throws QuicException {
        // Check flow control limit before accepting new data
        if (data.buf().remaining() > 0 && bufferedBytes + data.buf().remaining() > streamBufferCapacity) {
            // Reject fragment - exceeds maxStreamData limit
            data.release();
            throw new QuicException(
                    "MAX Data reached for stream#%d while adding bytes %d current buffered %d capacity %d"
                            .formatted(streamId, data.buf().remaining(), bufferedBytes, streamBufferCapacity),
                    QuicTransportError.STREAM_LIMIT_ERROR
            );
        }

        if (receivedFin && offset >= finOffset) {
            data.release();
            throw new QuicException(
                    "Received data ofder FIN on stream#%d offset %d finOffset %d"
                            .formatted(streamId, offset, finOffset),
                    QuicTransportError.STREAM_STATE_ERROR
            );
        }

        processFragment(offset, data, fin);

        // Check if we can advance the read pointer
        return hasContiguousData();
    }

    private void processFragment(long offset, PoolBuffer data, boolean fin) {
        if (data.buf().remaining() == 0) {
            if (fin) {
                receivedFin = true;
                finOffset = offset;
            }
            data.release();
            return;
        }

        // 1. Trim start if it overlaps with previous fragment
        Map.Entry<Long, PoolBuffer> prev = incomingFragments.floorEntry(offset);
        if (prev != null) {
            long prevEnd = prev.getKey() + prev.getValue().buf().remaining();
            if (prevEnd > offset) {
                int skip = (int) (prevEnd - offset);
                if (skip >= data.buf().remaining()) {
                    // Entirely covered by previous
                    data.release();
                    return;
                }
                data.buf().position(data.buf().position() + skip);
                offset = prevEnd;
            }
        }

        // 2. Check overlap with subsequent fragment(s)
        Long next = incomingFragments.ceilingKey(offset);
        if (next != null && next == offset) {
            // Already handled by ceilingKey returning exact match
            // We need to skip the part covered by 'next'
            PoolBuffer nextBuf = incomingFragments.get(next);
            long nextEnd = next + nextBuf.buf().remaining();
            int skip = (int) (nextEnd - offset);
            if (skip >= data.buf().remaining()) {
                data.release();
                return;
            }
            data.buf().position(data.buf().position() + skip);
            processFragment(nextEnd, data, fin);
            return;
        }

        if (next != null && offset + data.buf().remaining() > next) {
            // Overlaps with at least one next fragment.
            // We need to cut the portion before 'next' and process the rest recursively.

            long currentPortionLen = next - offset;
            if (currentPortionLen > 0) {
                // Store the piece before 'next'
                PoolBuffer firstPart = data.borrow();
                firstPart.buf().limit(firstPart.buf().position() + (int) currentPortionLen);
                incomingFragments.put(offset, firstPart);
                bufferedBytes += firstPart.buf().remaining();
            }

            // Advance data to 'next'
            int skip = (int) (next - offset);
            data.buf().position(data.buf().position() + skip);

            // Recurse to handle the remaining part of 'data' against fragments after 'next'
            processFragment(next, data, fin);
        } else {
            // No more overlaps, store the rest
            if (fin) {
                receivedFin = true;
                finOffset = offset + data.buf().remaining();
            }
            incomingFragments.put(offset, data);
            bufferedBytes += data.buf().remaining();
        }
    }

    /**
     * Reads available contiguous data from the buffer.
     * Called by worker thread to deliver data to handler.
     *
     * @return Available data starting from the next expected offset, or null if no data available
     */
    public StreamData readAvailableData() throws IOException {
        if (incomingFragments.isEmpty()) {
            return null;
        }

        // Build contiguous data
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        WritableByteChannel channel = Channels.newChannel(baos);

        while (!incomingFragments.isEmpty()) {
            Long firstOffset = incomingFragments.firstKey();

            // Check if this is the next expected fragment
            if (firstOffset > nextExpectedOffset) {
                break; // Gap in data
            }

            PoolBuffer fragment = incomingFragments.remove(firstOffset);

            // Decrease buffered bytes as we remove fragment
            bufferedBytes -= fragment.buf().remaining();

            // Handle overlapping or duplicate data
            if (firstOffset + fragment.buf().remaining() <= nextExpectedOffset) {
                // Already received this data, skip
                fragment.release();
                continue;
            }

            // Write the new portion
            int startIndex = (int) Math.max(0, nextExpectedOffset - firstOffset);
            ByteBuffer buf = fragment.buf().duplicate();
            buf.position(buf.position() + startIndex);
            int written = buf.remaining();
            channel.write(buf);
            nextExpectedOffset += written;

            fragment.release();
        }

        byte[] data = baos.toByteArray();
        if (data.length == 0) {
            return null;
        }

        // Check if this is the last data
        boolean isLast = receivedFin && nextExpectedOffset >= finOffset;

        return new StreamData(data, isLast);
    }

    /**
     * Gets the current number of buffered bytes (not yet delivered to application).
     */
    public long getBufferedBytes() {
        return bufferedBytes;
    }

    /**
     * Checks if there's contiguous data available to read.
     */
    private boolean hasContiguousData() {
        if (incomingFragments.isEmpty()) {
            return false;
        }
        return incomingFragments.firstKey() <= nextExpectedOffset;
    }

    public long getStreamId() {
        return streamId;
    }

    /**
     * Represents contiguous stream data ready to be delivered to the application.
     */
    public static class StreamData {
        private final byte[] data;
        private final boolean isLast;

        public StreamData(byte[] data, boolean isLast) {
            this.data = data;
            this.isLast = isLast;
        }

        public byte[] getData() {
            return data;
        }

        public boolean isLast() {
            return isLast;
        }
    }

    public void logIncomingFragments() {
        if (log.isDebugEnabled()) {
            for (Map.Entry<Long, PoolBuffer> entry : incomingFragments.entrySet()) {
                log.debug("Stream#{} Incoming Fragment: offset {}, bytes {}", streamId, entry.getKey(), entry.getValue().buf().remaining());
            }
        }
    }
}

