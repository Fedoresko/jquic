package org.fmalyshev.quic;

import org.fmalyshev.quic.buffers.PoolBuffer;

import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

public class CryptoFrameRebuilder {
    private int expectedLength = -1;
    private ByteBuffer continuousBuffer = null;

    // Segment tree index tracking: Key = Offset, Value = End Offset (Offset + Length)
    private final TreeMap<Integer, Integer> segments = new TreeMap<>();

    // Holds raw byte segments received BEFORE setExpectedLength is called
    private final TreeMap<Integer, PoolBuffer> earlyFragments = new TreeMap<>();

    // Tracks the total contiguous bytes available starting from offset 0
    private int contiguousHead = 0;

    public CryptoFrameRebuilder() {
        // Starts in dynamic staging mode, waiting for setExpectedLength
    }

    /**
     * Initializes the absolute memory boundaries for the completed frame.
     *
     * @param expectedLength The exact total size of the reassembled stream payload
     */
    public void setExpectedLength(int expectedLength) {
        if (expectedLength <= 0) {
            throw new IllegalArgumentException("Expected length must be greater than 0");
        }
        if (this.expectedLength != -1) {
            throw new IllegalStateException("Expected length has already been initialized");
        }

        this.expectedLength = expectedLength;
    }

    public int getExpectedLength() {
        return expectedLength;
    }

    /**
     * Add part of frame, if it overlaps existing parts, fill the gaps.
     * @param offset - offset in frame
     * @param length - length of part
     * @param data - part data
     * @return returns true if frame is complete
     * @throws IllegalStateException
     */
    public boolean addPart(int offset, int length, PoolBuffer data) throws IllegalStateException {
        int endOffset = offset + length;

        // 1. Boundary checking
        if (offset < 0 || length <= 0) {
            throw new IllegalStateException("Frame segment boundaries must be positive");
        }

        if (data.buf().remaining() < length) {
            throw new IllegalStateException("Provided ByteBuffer has fewer remaining bytes than specified length");
        }

        // 2. Split the new segment into gaps — only fill ranges not already covered.
        //
        // Strategy: walk through all existing segments that overlap [offset, endOffset)
        // and collect only the sub-intervals that are not yet present, then store each gap.

        // Snapshot the data bytes for the full new segment (we will index into it by position)
//        byte[] incoming = new byte[length];
//        data.buf().get(incoming);

        // Find the first existing segment whose end > offset (it may overlap from the left)
        Map.Entry<Integer, Integer> startEntry = segments.lowerEntry(endOffset);
        // Collect gaps: iterate from `offset` to `endOffset`, skipping covered ranges
        int gapStart = offset;

        // Gather all segments that could overlap [offset, endOffset)
        // floorEntry(offset) may start before `offset` but extend into it
        Map.Entry<Integer, Integer> floor = segments.floorEntry(offset);
        if (floor != null && floor.getValue() > offset) {
            // An existing segment already covers [offset .. floor.getValue())
            gapStart = floor.getValue();
        }

        while (gapStart < endOffset) {
            // Find the next existing segment that starts at or after gapStart
            Map.Entry<Integer, Integer> next = segments.ceilingEntry(gapStart);

            int gapEnd;
            if (next == null || next.getKey() >= endOffset) {
                // No existing segment blocks the rest — gap runs to endOffset
                gapEnd = endOffset;
            } else {
                // Gap runs up to the start of the next existing segment
                gapEnd = next.getKey();
            }

            if (gapEnd > gapStart) {
                // DoS protection: don't stage fragments beyond the budget
                if (gapEnd > 16384) {
                    throw new IllegalStateException("Exceeded unallocated buffer staging budget threshold");
                }
                // Extract the slice of `incoming` that covers [gapStart, gapEnd)
                int sliceOffset = gapStart - offset;
                int sliceLen    = gapEnd - gapStart;
//                byte[] slice = new byte[sliceLen];
//                System.arraycopy(incoming, sliceOffset, slice, 0, sliceLen);
                PoolBuffer fragment = data.borrow();
                fragment.buf().position(fragment.buf().position() + sliceOffset);
                fragment.buf().limit(fragment.buf().position() + sliceOffset + sliceLen);
                earlyFragments.put(gapStart, fragment);
                segments.put(gapStart, gapEnd);
            }

            // Advance past the existing segment that blocked us (if any)
            if (next == null || next.getKey() >= endOffset) {
                break;
            }
            gapStart = next.getValue(); // skip over the existing segment
        }

        data.buf().position(data.buf().position() + length);

        // 3. Advance the Contiguous Head Pointer
        while (segments.containsKey(contiguousHead)) {
            contiguousHead = segments.get(contiguousHead);
        }

        return isComplete();
    }

    public boolean isComplete() {
        return expectedLength != -1 && contiguousHead >= expectedLength;
    }

    /**
     * Prepares the combined data stream for reading loops
     * @return The underlying continuous buffer ready for the TLS engine
     * @throws IllegalStateException if called before the frame is complete
     */
    public ByteBuffer rebuild() {
        if (!isComplete()) {
            throw new IllegalStateException("Cannot rebuild frame: parts are still missing. Continuous head at: " + contiguousHead);
        }

        // Allocate direct if using for native I/O sockets, otherwise standard allocate
        this.continuousBuffer = ByteBuffer.allocate(contiguousHead);

        // Drain any early fragments that arrived out-of-order into our new fixed buffer
        for (Map.Entry<Integer, PoolBuffer> entry : earlyFragments.entrySet()) {
            if (entry.getKey() >= this.expectedLength) break;
            continuousBuffer.position(entry.getKey());
            continuousBuffer.put(entry.getValue().buf());
            entry.getValue().release();
        }
        // Clear early staging references to free JVM heap objects immediately
        earlyFragments.clear();

        continuousBuffer.clear(); // Position=0, Limit=expectedLength
        return continuousBuffer;
    }

    /**
     * Returns at most continuous {@numBytes} from the begging of frame.
     * @param numBytes - max bytes requested
     * @return continuous bytes buffer from the start of frame (presently known), not more than {@numBytes}
     */
    public ByteBuffer peekEarlyHead(int numBytes) {
        ByteBuffer temp = ByteBuffer.allocate(numBytes);
        int read = 0;
        while (read < numBytes) {
            PoolBuffer chunk = earlyFragments.get(read);
            if (chunk == null) break; // Gap in tree detected

            int toCopy = Math.min(chunk.buf().remaining(), numBytes - read);
            temp.put(chunk.buf().duplicate().limit(chunk.buf().position() + toCopy));
            read += toCopy;
        }
        temp.flip();
        return temp;
    }
}