package org.jquic.quic.buffers;

import org.jctools.queues.SpscLinkedQueue;
import org.jspecify.annotations.NonNull;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * This class supports writing in a zero-copy buffer with splitting data in chunks
 * It accepts a ByteBuffer large enough to contain all final data
 * It calls callback, that could wrap chunk data with some headers\trailers, and adjust buffer position to the start of the next chunk.
 * It supports goBack to update reserved placeholder with actual data\header.
 */
public class ChunkingOutputStream extends OutputStream {
    private ByteBuffer buf;
    private PoolBuffer pbuf;
    private final BufferPool pool;
    private final int chunkSize;
    private ChunkedOutputStreamWithAmendments.ChunkWrapper chunkWrapper;
    private int chunkStart;
    private int logicalOffset = 0;
    private final TreeMap<Integer, Integer> gaps = new TreeMap<>();
    private final SpscLinkedQueue<PoolBuffer> wrappedChunks = new SpscLinkedQueue<>();
    private final int capacity;
    private final long trailingPadding;
    private ChunkedOutputStreamWithAmendments.ChunkConsumer chunkConsumer;

    private boolean historyMode = false;
    private int lastPosition = 0;
    private int lastChunkStart = 0;
    private int firstChunkStart;
    private int lastBufferLogicalStart;
    private int position;
    private AtomicInteger lastUnreadOffset = new AtomicInteger(Integer.MAX_VALUE);

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
        if (capacity < chunkSize) {
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

        if (buf.remaining() == 0) {
            buf.position(0);
        }

        if (position - chunkStart == chunkSize || position >= unreadDataStart()) {
            triggerCallback(false);
        }
    }

    @Override
    public void write(byte @NonNull [] b, int off, int len) throws IOException {
        int bytesWritten = 0;
        while (bytesWritten < len) {
            int spaceLim = buf.remaining();

            int spaceLeft = (int)Math.min(unreadDataStart() - position, chunkSize - (position - chunkStart));
            int bytesToCopy = Math.min(Math.min(spaceLeft, len - bytesWritten), spaceLim);

            buf.put(b, off + bytesWritten, bytesToCopy);
            bytesWritten += bytesToCopy;
            position += bytesToCopy;
            if (!historyMode) {
                logicalOffset += bytesToCopy;
            }

            if (position - chunkStart == chunkSize || position >= unreadDataStart()) {
                triggerCallback(false);
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
        if (position < lastBufferLogicalStart || position >= logicalOffset) {
            throw new IllegalArgumentException("Invalid position: " + position + ". Current logical offset is " + logicalOffset + " Last buffer logical start is: "+ lastBufferLogicalStart);
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

    private void triggerCallback(boolean flush) throws IOException {
        if (historyMode) {
            Integer gapEnd = gaps.get(position);
            if (gapEnd == null) throw new IllegalStateException("Unexpected in history mode at position " + position);
            chunkStart = gapEnd;
            position = gapEnd;
            buf.position(position % capacity);
        } else {
            int start = chunkStart;
            int end = position;
            int chunkWrappedLen = end - start;
            int positionBeforeGap = position;
            ByteBuffer wrap = null;

            if (chunkWrappedLen > 0) {
                // Invoke user interception code - it must set adjust buffer position and limit back for continuation.
                int newLimit = positionBeforeGap % capacity;
                ByteBuffer chunk = buf.duplicate().position(chunkStart % capacity).limit(newLimit == 0 ? capacity : newLimit);
                wrap = (chunkWrapper != null) ?
                        chunkWrapper.wrapBuffer(chunk, logicalOffset - (positionBeforeGap - chunkStart) - lastBufferLogicalStart, flush)
                        : chunk;

                start = chunkStart + (wrap.position() - (chunkStart % capacity));
                end = chunkStart + (wrap.limit() - (chunkStart % capacity));
                chunkWrappedLen = wrap.remaining();
            }


            if (chunkWrappedLen > 0) {
                if (chunkStart + chunkWrappedLen > unreadDataStart()) {
                    throw new IllegalStateException("Buffer is full");
                }
                PoolBuffer pchunk = pbuf.borrow();
                pchunk.buf().position(start % capacity).limit(end % capacity);

                if (chunkConsumer != null) {
                    chunkConsumer.accept(pchunk);
                    int exch = lastUnreadOffset.compareAndExchange(Integer.MAX_VALUE, chunkWrappedLen);
                    if (exch != Integer.MAX_VALUE) {
                        lastUnreadOffset.addAndGet(chunkWrappedLen);
                    }
                } else {
                    wrappedChunks.offer(pchunk);
                }

                lastUnreadOffset.compareAndSet(Integer.MAX_VALUE, chunkStart);
            }

            if (chunkStart + chunkWrappedLen >= unreadDataStart()) {
                if (pbuf != null) {
                    pbuf.release();
                }
                lastBufferLogicalStart = logicalOffset;
                pbuf = pool.requestWriteBuffer();
                buf = pbuf.buf();
                chunkStart = buf.position();
                position = buf.position();
                firstChunkStart = chunkStart;
                lastUnreadOffset.set(Integer.MAX_VALUE);
                gaps.clear();
                System.out.println("Requested new Buffer");
            } else {

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
    }

    private long unreadDataStart() {
        return (long)lastUnreadOffset.get() + capacity - trailingPadding;
    }

    @Override
    public void close() throws IOException {
        super.close();
        if (pbuf != null) {
            pbuf.release();
            pbuf = null;
        }
    }

    // Need to wrap the last data that has not reached chunkSize yet.
    public void flush() throws IOException {
        toPresent();
        if (position > chunkStart) {
            triggerCallback(true);
        }
    }

    public PoolBuffer pollReadyChunk() {
        PoolBuffer chunk = wrappedChunks.poll();
        if (chunk != null) {
            int exch = lastUnreadOffset.compareAndExchange(Integer.MAX_VALUE, chunk.buf().remaining());
            if (exch != Integer.MAX_VALUE) {
                lastUnreadOffset.addAndGet(chunk.buf().remaining());
            }
        } else {
            if (pbuf != null) {
                pbuf.release();
                pbuf = null;
            }
        }
        return chunk;
    }


    public PoolBuffer peekReadyChunk() {
        return wrappedChunks.peek();
    }

    public int bufferedBytes() {
        int luo = lastUnreadOffset.get();
        return lastBufferLogicalStart + chunkStart - (luo == Integer.MAX_VALUE ? 0 : luo);
    }

    public Iterator<ByteBuffer> readyContentFrom(int pos) {
        if (historyMode) throw new IllegalStateException("Cant iterate content while in history mode");
        if (pos < lastBufferLogicalStart) throw new IllegalStateException("Position behind current buffer start");
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
                    res = buf.duplicate().position(curPos % capacity).limit(newLimit == 0 && position > curPos ? capacity : newLimit);
                    curPos = position;
                } else {
                    int newLimit = nextGap.getKey() % capacity;
                    res = buf.duplicate().position(curPos % capacity).limit(newLimit == 0 && nextGap.getKey() > curPos ? capacity : newLimit);
                    curPos = nextGap.getValue();
                }
                return res;
            }
        };
    }
}