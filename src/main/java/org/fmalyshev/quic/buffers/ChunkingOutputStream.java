package org.fmalyshev.quic.buffers;

import org.jspecify.annotations.NonNull;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.BiFunction;
import java.util.function.Consumer;

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
    private final TreeMap<Integer, Integer> gaps = new TreeMap<>();
    private final Deque<ReadyChunk> wrappedChunks = new LinkedList<>();
    private final int capacity;
    private Consumer<ByteBuffer> chunkConsumer;

    record ReadyChunk(int start, int end) {}

    private boolean historyMode = false;
    private int lastPosition = 0;
    private int lastChunkStart = 0;
    private final int firstChunkStart;
    private int position;

    /**
     * Create Stream
     *
     * @param buffer    - underlying buffer
     * @param chinkSize - size of max continuous data block before callback is called.
     */
    public ChunkingOutputStream(ByteBuffer buffer, int chinkSize) {
        this.chunkSize = chinkSize;
        this.buf = buffer;
        chunkStart = buf.position();
        position = buf.position();
        firstChunkStart = chunkStart;
        lastChunkStart = chunkStart;
        capacity = buffer.limit();
        if (capacity < chinkSize) {
            throw new IllegalArgumentException("Chunk size is more than buffer size");
        }
    }

    /**
     * Set call back which accepts ByteBuffer pointing to the last written chunk and logical offset - number
     * if the chunk's first byte written from the very beginning, excluding wrapping and amendments.
     */
    public void setCallback(BiFunction<ByteBuffer, Integer, ByteBuffer> callback) {
        this.chunkWrapper = callback;
    }

    public void setChunkConsumer(Consumer<ByteBuffer> consumer) {
        chunkConsumer = consumer;
    }

    @Override
    public void write(int b) throws IOException {
        buf.put((byte) b);
        if (!historyMode) {
            logicalOffset++;
        }
        position++;

        if (buf.remaining() == 0) {
            buf.position(0);
        }

        if (position - chunkStart == chunkSize) {
            triggerCallback();
        }
    }

    @Override
    public void write(byte @NonNull [] b, int off, int len) throws IOException {
        int bytesWritten = 0;
        while (bytesWritten < len) {
            int spaceLim = buf.remaining();

            int spaceLeft = chunkSize - (position - chunkStart);
            int bytesToCopy = Math.min(Math.min(spaceLeft, len - bytesWritten), spaceLim);

            buf.put(b, off + bytesWritten, bytesToCopy);
            bytesWritten += bytesToCopy;
            position += bytesToCopy;
            if (!historyMode) {
                logicalOffset += bytesToCopy;
            }

            if (position - chunkStart == chunkSize) {
                triggerCallback();
            }

            if (buf.remaining() == 0) {
                buf.position(0);
            }
        }
    }

    /**
     * Go to some previously written position to fill-in placeholder.
     * History mode if ON.
     *
     * @param position - position in underlying buffer.
     */
    public void goBack(int position) {
        if (position < 0 || position >= logicalOffset) {
            throw new IllegalArgumentException("Invalid position: " + position + ". Current logical offset is " + logicalOffset);
        }
        historyMode = true;
        LogicalPosition pos = getLogicalPosition(position);
        if (this.position - (pos.chunkStart() + pos.rpos()) > capacity) {
            throw new IllegalArgumentException("Can't go too way back");
        }
        lastChunkStart = this.chunkStart;
        this.chunkStart = pos.chunkStart();
        lastPosition = this.position;
        this.position = pos.chunkStart() + pos.rpos();
        buf.position(this.position % capacity);
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
            position = lastPosition;
            buf.position(lastPosition % capacity);
            chunkStart = lastChunkStart;
        }
    }

    private void triggerCallback() {
        if (historyMode) {
            Integer gapEnd = gaps.get(position);
            if (gapEnd == null) throw new IllegalStateException("Unexpected in history mode at position " + position);
            chunkStart = gapEnd;
            position = gapEnd;
            buf.position(position % capacity);
        } else {
            int positionBeforeGap = position;

            // Invoke user interception code - it must set adjust buffer position and limit back for continuation.
            int newLimit = positionBeforeGap % capacity;
            ByteBuffer chunk = buf.duplicate().position(chunkStart % capacity).limit(newLimit == 0 ? capacity : newLimit);
            ByteBuffer wrap = (chunkWrapper != null) ?
                    chunkWrapper.apply(chunk, logicalOffset - (positionBeforeGap - chunkStart))
                    : chunk;

            int start = chunkStart + (wrap.position() - (chunkStart % capacity));
            int end = chunkStart + (wrap.limit() - (chunkStart % capacity));
            int chunkWrappedLen = wrap.remaining();

            if (chunkConsumer != null) {
                chunkConsumer.accept(wrap);
            } else {
                if (!wrappedChunks.isEmpty() && wrappedChunks.peek().start + capacity < end) {
                    throw new IllegalStateException("Buffer is full");
                }
                wrappedChunks.offer(new ReadyChunk(start, end));
            }

            int advance = chunkWrappedLen > chunkSize ? chunkWrappedLen - chunkSize : 0;

            if (buf.remaining() < Math.max(chunkWrappedLen, chunkSize)) {
                int headerSize = Math.max(0, chunkStart - start);
                advance = buf.remaining() + headerSize;
            }

            position += advance;

            chunkStart = position;
            buf.position(position % capacity);
            buf.limit(capacity);
            gaps.put(positionBeforeGap, chunkStart);
        }
    }

    // Need to wrap the last data that has not reached chunkSize yet.
    public void flush() {
        toPresent();
        if (position > chunkStart) {
            triggerCallback();
        }
    }

    public ByteBuffer pollReadyChunk() {
        ReadyChunk chunk = wrappedChunks.poll();
        return chunk == null ? null : buf.duplicate().position(chunk.start % capacity).limit(chunk.end % capacity);
    }

    public Iterator<ByteBuffer> readyContentFrom(int pos) {
        if (historyMode) throw new IllegalStateException("Cant iterate content while in history mode");
        LogicalPosition lpos = getLogicalPosition(pos);
        int curPos = lpos.chunkStart() + lpos.rpos();
        if (position - curPos > capacity) throw new IllegalArgumentException("Start position is too early away.");

        return new Iterator<ByteBuffer>() {
            int curPos = lpos.chunkStart() + lpos.rpos();


            @Override
            public boolean hasNext() {
                return (curPos < position);
            }

            @Override
            public ByteBuffer next() {
                if (curPos >= position)
                    throw new NoSuchElementException();
                Map.Entry<Integer, Integer> nextGap = gaps.ceilingEntry(curPos + 1);

                ByteBuffer res;
                if (nextGap == null) {
                    int newLimit = position % capacity;
                    res = buf.duplicate().position(curPos % capacity).limit(newLimit == 0 ? capacity : newLimit);
                    curPos = position;
                } else {
                    int newLimit = nextGap.getKey() % capacity;
                    res = buf.duplicate().position(curPos % capacity).limit(newLimit == 0 ? capacity : newLimit);
                    curPos = nextGap.getValue();
                }
                return res;
            }
        };
    }
}