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

import org.jquic.quic.streamapi.QuicConnectionControl;
import org.jquic.quic.struct.SortedIntervals;
import org.jquic.quic.struct.TriStateQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Tracks the state and metadata of a single QUIC stream.
 */
public class StreamState {
    private static final Logger log = LoggerFactory.getLogger(StreamState.class);

    public long getBufferedBytes() {
        return bufferedBytes;
    }

    public void setBufferedBytes(long bufferedBytes) {
        this.bufferedBytes = bufferedBytes;
    }

    public TriStateQueue<ApplicationData> getSendQueue() {
        return sendQueue;
    }

    /**
     * Stream lifecycle states (RFC 9000 Section 3)
     */
    public enum State {
        IDLE,           // Stream not yet created
        OPEN,           // Stream open for sending/receiving
        HALF_CLOSED_LOCAL,   // Local side sent FIN
        HALF_CLOSED_REMOTE,  // Remote side sent FIN
        CLOSED,         // Stream fully closed
        RESET_SENT,     // RESET_STREAM sent
        RESET_ACK_RECEIVED;  // ACK for RESET_STREAM received

        public boolean canReceive() {
            return this == State.OPEN || this == State.HALF_CLOSED_LOCAL || this == State.RESET_SENT;
        }
        public boolean canSend() {
            return this == State.OPEN || this == State.HALF_CLOSED_REMOTE;
        }
    }

    private final TriStateQueue<ApplicationData> sendQueue = new TriStateQueue<>(ApplicationData.EMPTY, ApplicationData.PROCESSED);

    private final long streamId;
    final QuicConnectionControl.StreamType streamType;
    private State state;

    // Flow control
    private final AtomicLong maxStreamData; // Maximum data we can send (peer's limit)
    private long remoteMaxStreamData; // Maximum data remote can send (our limit)
    private volatile long maxSentOffset;     // Total bytes sent (cumulative)
    private long maxOffset;           // Total bytes received (cumulative)
    private long inFlightBytes;       // Bytes sent but not yet acknowledged
    private long bufferedBytes;       // Bytes in receive buffer
    AtomicLong lastDataBlockedAt  = new AtomicLong(0);
    Map<Long, Long> ackedIntervals = new HashMap<>();
    private long maxAckedOffset = 0;
    private long sumAckedLen = 0;


    public StreamState(long streamId, QuicConnectionControl.StreamType streamType,
                      long initialMaxStreamDataToSend, long initialMaxStreamToReceive) {
        this.streamId = streamId;
        this.streamType = streamType;
        this.state = State.OPEN;
        this.maxStreamData = new AtomicLong(initialMaxStreamDataToSend);
        this.remoteMaxStreamData = initialMaxStreamToReceive;
        this.maxSentOffset = 0;
        this.maxOffset = 0;
        this.inFlightBytes = 0;
        this.setBufferedBytes(0);
    }

    public long getStreamId() {
        return streamId;
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }

    public boolean isBidirectional() {
        return streamType == QuicConnectionControl.StreamType.Bidirectional;
    }

    public long getMaxStreamData() {
        return maxStreamData.get();
    }

    public void setMaxStreamData(long maxStreamData) {
        this.maxStreamData.set(maxStreamData);
    }

    public long getRemoteMaxStreamData() {
        return remoteMaxStreamData;
    }

    public void setRemoteMaxStreamData(long remoteMaxStreamData) {
        this.remoteMaxStreamData = remoteMaxStreamData;
    }

    public long getMaxSentOffset() {
        return maxSentOffset;
    }

    public long updateMaxSentOffset(long offset) {
        long prevOffset = maxSentOffset;
        if (offset > prevOffset) {
            maxSentOffset = offset;
            this.inFlightBytes += offset - prevOffset;
            return offset - prevOffset;
        }
        return 0;
    }

    public long getMaxOffset() {
        return maxOffset;
    }

    public long updateMaxOffset(long offset) {
        long prevOffset = maxOffset;
        maxOffset = Math.max(maxOffset, offset);
        return maxOffset - prevOffset;
    }

    public long onBytesAcknowledged(long offset, long length) {
        if (maxAckedOffset < offset + length) maxAckedOffset = offset + length;
        if (!ackedIntervals.containsKey(offset)) {
            ackedIntervals.put(offset, offset + length);
            sumAckedLen += length;
            inFlightBytes -= length;
            return length;
        }
        log.info("Acknowledged offset {}, length {}, maxAckOffset {}, sumAckedBytes {}", offset, length, maxAckedOffset, sumAckedLen);
        return 0;
    }

    public boolean canSendBytes(long bytes) {
        // Check if we can send 'bytes' without exceeding peer's limit
        return (maxSentOffset + bytes) <= maxStreamData.get();
    }
}

