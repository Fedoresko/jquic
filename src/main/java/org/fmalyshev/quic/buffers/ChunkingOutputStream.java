package org.fmalyshev.quic.buffers;

import org.jspecify.annotations.NonNull;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.BiFunction;

/**
 * This class supports writing in a zero-copy buffer with splitting data in chunks
 * It accepts a ByteBuffer large enough to contain all final data
 * It calls callback, that could wrap chunk data with some headers\trailers, and adjust buffer position to the start of the next chunk.
 * It supports goBack to update reserved placeholder with actual data\header.
 */
public class ChunkingOutputStream extends OutputStream {
    private final ByteBuffer buf;
    private final int chunkSize;
    private BiFunction<ByteBuffer, Integer, ByteBuffer> chunkWrapper;
    private int chunkStart;
    private int logicalOffset = 0;
    private TreeMap<Integer, Integer> gaps = new TreeMap<>();
    private List<ByteBuffer> wrappedChunks = new ArrayList<>();
    private int originalLimit;

    private boolean historyMode = false;
    private int lastPosition = 0;
    private int lastChunkStart = 0;
    private final int firstChunkStart;

    /**
     * Create Stream
     * @param buffer - underlying buffer
     * @param chinkSize - size of max continuous data block before callback is called.
     */
    public ChunkingOutputStream(ByteBuffer buffer, int chinkSize) {
        this.chunkSize = chinkSize;
        this.buf = buffer;
        chunkStart = buf.position();
        firstChunkStart = chunkStart;
        lastChunkStart = chunkStart;
        originalLimit = buffer.limit();
    }

    /**
     * Set call back which accepts ByteBuffer pointing to the last written chunk and logical offset - number
     * if the chunk's first byte written from the very beginning, excluding wrapping and amendments.
     */
    public void setCallback(BiFunction<ByteBuffer, Integer, ByteBuffer> callback) {
        this.chunkWrapper = callback;
    }

    @Override
    public void write(int b) throws IOException {
        buf.put((byte) b);
        if (!historyMode) {
            logicalOffset++;
        }

        if (buf.position() - chunkStart == chunkSize) {
            triggerCallback();
        }
    }

    /**
     * Go to some previously written position to fill-in placeholder.
     * History mode if ON.
     * @param position - position in underlying buffer.
     */
    public void goBack(int position) {
        if (position < 0 || position >= logicalOffset) {
            throw new IllegalArgumentException("Invalid position: " + position + ". Current logical offset is " + logicalOffset);
        }
        historyMode = true;
        LogicalPosition pos = getLogicalPosition(position);
        lastChunkStart = this.chunkStart;
        this.chunkStart = pos.chunkStart();
        lastPosition = buf.position();
        buf.position(pos.chunkStart() + pos.rpos());
    }

    private @NonNull LogicalPosition getLogicalPosition(int position) {
        int nChunk = position / chunkSize;
        int rpos = position % chunkSize;
        Integer chunkStart = firstChunkStart;
        for (int i = 0; i < nChunk; i++) {
            chunkStart = gaps.get(chunkStart + chunkSize);
            if (chunkStart == null) throw new IndexOutOfBoundsException();
        }
        return new LogicalPosition(rpos, chunkStart);
    }

    private record LogicalPosition(int rpos, Integer chunkStart) {
    }

    /**
     * @return - current logical offset - number of bytes written.
     */
    public int getPos() {
        return logicalOffset;
    }

    /**
     * Reset position back to the tail of the buffer. History mode if OFF.
     */
    public void toPresent() {
        if (historyMode) {
            historyMode = false;
            buf.position(lastPosition);
            chunkStart = lastChunkStart;
        }
    }

    @Override
    public void write(byte @NonNull [] b, int off, int len) throws IOException {
        int bytesWritten = 0;
        while (bytesWritten < len) {
            int spaceLeft = chunkSize - (buf.position() - chunkStart);
            int bytesToCopy = Math.min(spaceLeft, len - bytesWritten);

            buf.put(b, off + bytesWritten, bytesToCopy);
            bytesWritten += bytesToCopy;
            if (!historyMode) {
                logicalOffset += bytesToCopy;
            }

            if (buf.position() - chunkStart == chunkSize) {
                triggerCallback();
            }
        }
    }

    private void triggerCallback() {
        if (historyMode) {
            Integer gapEnd = gaps.get(buf.position());
            if (gapEnd == null) throw new IllegalStateException("Unexpected in history mode at position " + buf.position());
            chunkStart = gapEnd;
            buf.position(chunkStart);
        } else {
            int positionBeforeGap = buf.position();

            // Invoke user interception code - it must set adjust buffer position and limit back for continuation.
            if (chunkWrapper != null) {
                wrappedChunks.add( chunkWrapper.apply(buf.position(chunkStart).limit(positionBeforeGap), logicalOffset - (positionBeforeGap - chunkStart)) );
            }

            chunkStart = buf.position();
            buf.limit(originalLimit);
            gaps.put(positionBeforeGap, chunkStart);
        }
    }

    // Need to wrap the last data that has not reached chunkSize yet.
    public void flush() {
        toPresent();
        if (buf.position() > chunkStart) {
            triggerCallback();
        }
    }

    public Iterable<ByteBuffer> readyChunks() {
        return wrappedChunks;
    }

    public Iterator<ByteBuffer> readyContentFrom(int position) {
        if (historyMode) throw new IllegalStateException("Cant iterate content while in history mode");
        return new Iterator<ByteBuffer>() {

            LogicalPosition pos = getLogicalPosition(position);
            int curPos = pos.chunkStart() + pos.rpos();

            @Override
            public boolean hasNext() {
                return (curPos < buf.position());
            }

            @Override
            public ByteBuffer next() {
                if  (curPos >= buf.position())
                    throw new NoSuchElementException();
                Map.Entry<Integer, Integer> nextGap = gaps.ceilingEntry(curPos);

                ByteBuffer res;
                if (nextGap == null) {
                    res = buf.duplicate().position(curPos).limit(buf.position());
                    curPos = buf.position();
                } else {
                    res = buf.duplicate().position(curPos).limit(nextGap.getKey());
                    curPos = nextGap.getValue();
                }
                return res;
            }
        };
    }
}