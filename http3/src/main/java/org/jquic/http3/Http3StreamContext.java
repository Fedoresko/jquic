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
package org.jquic.http3;

import org.jquic.quic.QuicVarint;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Deque;
import java.util.LinkedList;

/**
 * Context for a single HTTP/3 stream.
 */
public class Http3StreamContext extends InputStream {
    enum RequestProcessingState {
        INITIAL,
        WAITING_FOR_BODY,
        WAITING_FOR_FIN,
        RESPONSE_SENDING,
        FINISHED,
    }

    record ParsedFrame(long type, byte[] payload) {
        ByteBuffer payloadAsBuffer() {
            return ByteBuffer.wrap(payload);
        }
    }

    private final Deque<ByteBuffer> chunks = new LinkedList<>();
    private int bufferedBytes = 0;

    /**
     * HTTP/3-level role of this stream.
     */
    private @Nullable Http3ClientStreamRole role;

    // ---- request state machine ----
    private RequestProcessingState requestState = RequestProcessingState.INITIAL;
    private Http3Request request;

    private StreamWrapper streamWrapper;

    public int readBodyBytes = 0;

    public Http3StreamContext(@Nullable Http3ClientStreamRole role) {
        setRole(role);
    }

    @Nullable Http3ClientStreamRole getRole() {
        if (role == null) {
            Long type = tryReadStreamType();
            if (type != null) {
                setRole(Http3ClientStreamRole.fromStreamType(type));
            }
        }
        return role;
    }



    private void setRole(Http3ClientStreamRole role) {
        this.role = role;
        if (role == Http3ClientStreamRole.REQUEST || role == Http3ClientStreamRole.CONTROL) {
            streamWrapper = new FramedStreamWrapper(this);
        } else if (role == Http3ClientStreamRole.QPACK_ENCODER || role == Http3ClientStreamRole.QPACK_DECODER) {
            streamWrapper = new QpackStreamWrapper(this);
        }
    }

    public StreamWrapper getStreamWrapper() {
        return streamWrapper;
    }

    RequestProcessingState getRequestState() {
        return requestState;
    }

    void setRequestState(RequestProcessingState state) {
        this.requestState = state;
    }

    Http3Request getRequest() {
        return request;
    }

    void setRequest(Http3Request request) {
        this.request = request;
    }

    boolean hasUnconsumedData() {
        return bufferedBytes > 0;
    }

    @Override
    public int read() throws IOException {
        if (!chunks.isEmpty() && chunks.peek().remaining() == 0) chunks.poll();
        if (chunks.isEmpty()) return -1;
        bufferedBytes--;
        return chunks.peek().get() & 0xFF;
    }

    void appendData(byte[] data) {
        chunks.add(ByteBuffer.wrap(data));
        bufferedBytes += data.length;
    }

    private void consume(int n) {
        bufferedBytes -= n;
        while (n > 0 && !chunks.isEmpty()) {
            ByteBuffer chunk = chunks.peek();
            int toConsume = Math.min(n, chunk.remaining());
            chunk.position(chunk.position() + toConsume);
            n -= toConsume;
            if (chunk.remaining() == 0) chunks.poll();
        }
    }

    /**
     * Peeks a varint from the buffered chunks at the specified offset from the current read position.
     * Returns null if not enough data is available.
     */
    private @Nullable Long peekVarint(int skipBytes) {
        byte[] peekBuf = new byte[8];
        int available = 0;
        int skipped = 0;
        for (ByteBuffer chunk : chunks) {
            ByteBuffer dupe = chunk.duplicate();
            if (skipped < skipBytes) {
                int toSkip = Math.min(dupe.remaining(), skipBytes - skipped);
                dupe.position(dupe.position() + toSkip);
                skipped += toSkip;
            }
            if (skipped == skipBytes) {
                int toCopy = Math.min(dupe.remaining(), 8 - available);
                dupe.get(peekBuf, available, toCopy);
                available += toCopy;
                if (available == 8) break;
            }
        }
        if (available == 0) return null;
        int firstByte = peekBuf[0] & 0xFF;
        int len = 1 << (firstByte >> 6);
        if (available < len) return null;
        return QuicVarint.read(ByteBuffer.wrap(peekBuf));
    }

    /**
     * Attempts to read the leading stream-type varint for a unidirectional stream.
     */
    @Nullable
    private Long tryReadStreamType() {
        Long type = peekVarint(0);
        if (type != null) {
            consume(QuicVarint.sizeOf(type));
            return type;
        }
        return null;
    }


}
