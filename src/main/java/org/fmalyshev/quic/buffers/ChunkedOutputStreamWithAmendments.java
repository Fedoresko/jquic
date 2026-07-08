package org.fmalyshev.quic.buffers;

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

    /**
     * Go to some previously written position to fill-in placeholder.
     * Writes performed by @{writer} would amend previously written data inplace (filling placeholders).
     * @param position - position in underlying buffer.
     * @param writer - writer to put some amendments in place
     */
    public abstract void amendAtPos(int position, Writer writer) throws IOException;

    /**
     * Returns position for goBacks, readyContentFrom, and other...
     * @return - current logical offset (number of bytes written).
     */
    public abstract int getPos();

    /**
     * Get ready and wrapped chunks.
     * Expected to contain all data after Stream is closed but could yeld intermediate results.
     * @return iterable chunk data.
     */
    public abstract Iterable<ByteBuffer> readyChunks();

    /**
     * Get unwrapped (original) data only starting from the provided position until the current position.
     * @throws IllegalStateException if in history mode.
     * @param position - position to get data from
     * @return - sequence of buffers containing data (if data split to different chunks there would be two and more of them).
     */
    public abstract Iterable<ByteBuffer> readyContentFrom(int position);
}
