package org.jquic.quic.buffers;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;


public abstract class ChunkedOutputStreamWithAmendments extends DataOutputStream {
    public ChunkedOutputStreamWithAmendments(OutputStream out) {
        super(out);
    }

    public interface Writer {
        void write(DataOutputStream dos) throws IOException;
    }

    public interface ChunkWrapper {
        ByteBuffer wrapBuffer(ByteBuffer buf, int offset, boolean isFinal);
    }

    public interface ChunkConsumer {
        void accept(PoolBuffer buf) throws IOException;
    }

    /**
     * Set chunk consumer.
     * It is expected that pollReadyChunk would always return null if consumer is set.
     *
     * @param consumer called immediately to consume chunk when ready.
     */
    public abstract void setChunkConsumer(ChunkConsumer consumer);

    /**
     * Go to some previously written position to fill-in placeholder.
     * Writes performed by @{writer} would amend previously written data inplace (filling placeholders).
     *
     * @param position - position in underlying buffer.
     * @param writer   - writer to put some amendments in place
     */
    public abstract void amendAtPos(int position, Writer writer) throws IOException;

    /**
     * Returns position for goBacks, readyContentFrom, and other...
     *
     * @return - current logical offset (number of bytes written).
     */
    public abstract int getPos();

    /**
     * Poll ready and wrapped chunk.
     *
     * @return the first added chunk in queue, null if nothing left.
     */
    public abstract PoolBuffer pollReadyChunk();

    /**
     * Peek at ready and wrapped chunk.
     *
     * @return the first added chunk in queue, null if nothing left.
     */
    public abstract PoolBuffer peekReadyChunk();

    /**
     * Return total data already available to poll
     */
    public abstract int bufferedBytes();

    /**
     * Return if the stream was closed
     */
    public abstract boolean isClosed();

    /**
     * Get unwrapped (original) data only starting from the provided position until the current position.
     *
     * @param position - position to get data from
     * @return - sequence of buffers containing data (if data split to different chunks there would be two and more of them).
     * @throws IllegalStateException if in history mode.
     */
    public abstract Iterable<ByteBuffer> readyContentFrom(int position);
}
