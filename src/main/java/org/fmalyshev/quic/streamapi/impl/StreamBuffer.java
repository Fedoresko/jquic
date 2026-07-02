package org.fmalyshev.quic.streamapi.impl;

import org.fmalyshev.quic.buffers.PoolBuffer;

import java.io.IOException;
import java.nio.channels.Channels;
import java.nio.channels.WritableByteChannel;
import java.util.TreeMap;

/**
 * Buffers incoming and outgoing data for a single QUIC stream.
 * Handles out-of-order frame arrival and reassembly.
 * Thread-safety: ALL methods are called from worker thread only - no synchronization needed.
 */
public class StreamBuffer {
    private final long streamId;
    private final int streamBufferCapacity;

    // Incoming data buffer for reassembly (offset -> data)
    private final TreeMap<Long, PoolBuffer> incomingFragments = new TreeMap<>();
    private long nextExpectedOffset = 0;
    private boolean receivedFin = false;
    private long finOffset = -1;

    // Flow control tracking
    private long bufferedBytes = 0; // Bytes buffered but not yet delivered to application

    // Outgoing data tracking
    private long nextSendOffset = 0;

    public StreamBuffer(long streamId, int streamBufferCapacity) {
        this.streamId = streamId;
        this.streamBufferCapacity = streamBufferCapacity;
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
    public boolean addIncomingData(long offset, PoolBuffer data, boolean fin) {
        // Check flow control limit before accepting new data
        if (data.buf().remaining() > 0 && bufferedBytes + data.buf().remaining() > streamBufferCapacity) {
            // Reject fragment - exceeds maxStreamData limit
            data.release();
            return false;
        }

        // Store the fragment
        if (data.buf().remaining() > 0) {
            incomingFragments.put(offset, data);
            bufferedBytes += data.buf().remaining();
        }

        // Track FIN
        if (fin) {
            receivedFin = true;
            finOffset = offset + data.buf().remaining();
        }

        // Check if we can advance the read pointer
        return hasContiguousData();
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
                continue;
            }

            // Write the new portion
            int startIndex = (int) Math.max(0, nextExpectedOffset - firstOffset);
            channel.write(fragment.buf().duplicate().position(fragment.buf().position() + startIndex));
            nextExpectedOffset = firstOffset + fragment.buf().remaining();

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

    /**
     * Gets and increments the next send offset for outgoing data.
     * Called when application sends data on this stream.
     */
    public long allocateSendOffset(int dataLength) {
        long offset = nextSendOffset;
        nextSendOffset += dataLength;
        return offset;
    }

    /**
     * Returns whether the stream has received FIN.
     */
    public boolean hasReceivedFin() {
        return receivedFin;
    }

    /**
     * Gets the current receive offset.
     */
    public long getNextExpectedOffset() {
        return nextExpectedOffset;
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
}
