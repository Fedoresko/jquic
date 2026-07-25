package org.jquic.quic.buffers;

import org.jctools.queues.SpscLinkedQueue;
import org.jspecify.annotations.NonNull;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.*;

/**
 * Alternative implementation of ChunkingOutputStream that does not use wrap-around.
 * It allocates a new buffer from the pool when the current one is full.
 */
public class ChunkingOutputStream extends OutputStream {
    private ByteBuffer buf;
    private volatile PoolBuffer pbuf;
    private final BufferPool pool;
    private final int chunkSize;
    private ChunkedOutputStreamWithAmendments.ChunkWrapper chunkWrapper;
    private int chunkStart;
    private int logicalOffset = 0;
    private final TreeMap<Integer, Integer> gaps = new TreeMap<>();
    private final SpscLinkedQueue<PoolBuffer> wrappedChunks = new SpscLinkedQueue<>();
    private final int capacity;
    private final int trailingPadding;
    private ChunkedOutputStreamWithAmendments.ChunkConsumer chunkConsumer;

    private boolean historyMode = false;
    private int lastPosition = 0;
    private int lastChunkStart = 0;
    private int firstChunkStart;
    private int lastBufferLogicalStart;
    private int position;
    private boolean isClosed = false;

    /**
     * Create Stream
     *
     * @param pool    - buffer pool
     * @param chunkSize - size of max continuous data block before callback is called.
     */
    public ChunkingOutputStream(BufferPool pool, int chunkSize, int trailingPadding) {
        this.pool = pool;
        this.chunkSize = chunkSize;
        this.pbuf = pool.requestWriteBuffer();
        this.buf = pbuf.buf();
        chunkStart = buf.position();
        position = buf.position();
        firstChunkStart = chunkStart;
        capacity = buf.limit();
        lastBufferLogicalStart = 0;
        this.trailingPadding = trailingPadding;
        if (buf.remaining() < chunkSize + trailingPadding) {
            throw new IllegalArgumentException("Chunk size is more than buffer size");
        }
    }

    /**
     * Set call back which accepts ByteBuffer pointing to the last written chunk and logical offset - number
     * if the chunk's first byte written from the very beginning, excluding wrapping and amendments.
     */
    public void setCallback(ChunkedOutputStreamWithAmendments.ChunkWrapper callback) {
        this.chunkWrapper = callback;
    }

    public void setChunkConsumer(ChunkedOutputStreamWithAmendments.ChunkConsumer consumer) {
        chunkConsumer = consumer;
    }

    @Override
    public void write(int b) throws IOException {
        buf.put((byte) b);
        if (!historyMode) {
            logicalOffset++;
        }
        position++;

        if (position - chunkStart == chunkSize || atTheBufferEdge()) {
            triggerCallback();
        }
    }

    @Override
    public void write(byte @NonNull [] b, int off, int len) throws IOException {
        int bytesWritten = 0;
        while (bytesWritten < len) {
            int spaceLim = Math.max(0, buf.remaining() - trailingPadding);

            int spaceLeft = Math.min(chunkSize - (position - chunkStart), spaceLim);
            int bytesToCopy = Math.min(spaceLeft, len - bytesWritten);

            buf.put(b, off + bytesWritten, bytesToCopy);
            bytesWritten += bytesToCopy;
            position += bytesToCopy;
            if (!historyMode) {
                logicalOffset += bytesToCopy;
            }

            if (position - chunkStart == chunkSize || atTheBufferEdge()) {
                triggerCallback();
            }
        }
    }

    private void triggerCallback() throws IOException {
        if (historyMode) {
            Integer gapEnd = gaps.get(position);
            if (gapEnd == null) throw new IllegalStateException("Unexpected in history mode at position " + position);
            chunkStart = gapEnd;
            position = gapEnd;
            buf.position(position);
        } else {
            int start = chunkStart;
            int end = position;
            int chunkWrappedLen = end - start;
            int positionBeforeGap = position;
            ByteBuffer wrap = null;

            if (chunkWrappedLen > 0) {
                // Invoke user interception code - it must set adjust buffer position and limit back for continuation.
                ByteBuffer chunk = buf.duplicate().position(chunkStart).limit(position);
                wrap = (chunkWrapper != null) ?
                        chunkWrapper.wrapBuffer(chunk, logicalOffset - (position - chunkStart), isClosed())
                        : chunk;

                start = wrap.position();
                end = wrap.limit();
                chunkWrappedLen = wrap.remaining();
            }

            if (chunkWrappedLen > 0) {
                if (pbuf != null) {
                    PoolBuffer borrow = pbuf.borrow();
                    borrow.buf().position(start).limit(end);
                    if (chunkConsumer != null) {
                        chunkConsumer.accept(borrow);
                    } else {
                        wrappedChunks.offer(borrow);
                    }
                }
            }

            int advance = (chunkWrappedLen > chunkSize ? chunkWrappedLen - chunkSize : 0) + trailingPadding;

            if (buf.limit() - position <= advance + trailingPadding) {
                if (pbuf != null) {
                    pbuf.release();
                    pbuf = pool.requestWriteBuffer();

                    buf = pbuf.buf();
                    position = buf.position();
                    if (buf.limit() < chunkSize + trailingPadding) {
                        throw new IllegalArgumentException("Chunk size is more than buffer size");
                    }
                    positionBeforeGap = position;
                    lastBufferLogicalStart = logicalOffset;
                    gaps.clear();
                }
            } else {
                position += advance;
            }

            chunkStart = position;
            buf.position(position);
            if (positionBeforeGap != chunkStart) {
                gaps.put(positionBeforeGap, chunkStart);
            }
        }
    }

    @Override
    public void close() throws IOException {
        if(!isClosed) {
            isClosed = true;
            flush();
            if (pbuf != null) {
                pbuf.release();
                pbuf = null;
            }
        }
    }

    // Need to wrap the last data that has not reached chunkSize yet.
    public void flush() throws IOException {
        toPresent();
        if (position > chunkStart) {
            triggerCallback();
        }
    }

    public PoolBuffer pollReadyChunk() {
        return wrappedChunks.poll();
    }

    public PoolBuffer peekReadyChunk() {
        return wrappedChunks.peek();
    }

    private boolean isClosed() {
        return isClosed;
    }

    private boolean atTheBufferEdge() {
        return buf.remaining() <= trailingPadding;
    }

    /**
     * Go to some previously written position to fill-in placeholder.
     * History mode if ON.
     *
     * @param logicalPos - position in underlying buffer.
     */
    public void goBack(int logicalPos) {
        if (logicalPos < lastBufferLogicalStart || logicalPos >= logicalOffset) {
            throw new IllegalArgumentException("Invalid position: " + logicalPos + ". Current logical offset is " + logicalOffset + " Last buffer logical start is: "+ lastBufferLogicalStart);
        }
        historyMode = true;
        LogicalPosition pos = getLogicalPosition(logicalPos);
        if (this.position - (pos.chunkStart() + pos.rpos()) > capacity) {
            throw new IllegalArgumentException("Can't go too way back");
        }
        lastChunkStart = this.chunkStart;
        this.chunkStart = pos.chunkStart();
        lastPosition = this.position;
        this.position = pos.chunkStart() + pos.rpos();
        buf.position(this.position);
    }


    private record LogicalPosition(int rpos, Integer chunkStart) {
    }

    private @NonNull LogicalPosition getLogicalPosition(int position) {
        position -= lastBufferLogicalStart;
        int nChunk = position / chunkSize;
        int rpos = position % chunkSize;
        Integer chunkStart = firstChunkStart;
        for (int i = 0; i < nChunk; i++) {
            chunkStart = gaps.get(chunkStart + chunkSize);
            if (chunkStart == null) throw new IndexOutOfBoundsException();
        }
        return new LogicalPosition(rpos, chunkStart);
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
            buf.position(lastPosition );
            chunkStart = lastChunkStart;
        }
    }

    public Iterator<ByteBuffer> readyContentFrom(int pos) {
        if (historyMode) throw new IllegalStateException("Cant iterate content while in history mode");
        if (pos < lastBufferLogicalStart) throw new IllegalStateException("Position behind current buffer start");
        LogicalPosition lpos = getLogicalPosition(pos);
        int curPos = lpos.chunkStart() + lpos.rpos();
        if (position - curPos > capacity) throw new IllegalArgumentException("Start position is too early away.");

        return new Iterator<>() {
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
                    int newLimit = position;
                    res = buf.duplicate().position(curPos).limit(newLimit == 0 && position > curPos ? capacity : newLimit);
                    curPos = position;
                } else {
                    int newLimit = nextGap.getKey();
                    res = buf.duplicate().position(curPos).limit(newLimit == 0 && nextGap.getKey() > curPos ? capacity : newLimit);
                    curPos = nextGap.getValue();
                }
                return res;
            }
        };
    }
}
