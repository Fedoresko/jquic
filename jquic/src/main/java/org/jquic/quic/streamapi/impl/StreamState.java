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

/**
 * Tracks the state and metadata of a single QUIC stream.
 */
public class StreamState {
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

    private final long streamId;
    private final boolean isServerInitiated;
    final QuicConnectionControl.StreamType streamType;
    private State state;

    // Flow control
    private long maxStreamData;        // Maximum data we can send (peer's limit)
    private long remoteMaxStreamData;  // Maximum data remote can send (our limit)
    private long sentBytes;            // Total bytes sent (cumulative)
    private long maxOffset;        // Total bytes received (cumulative)
    private long inFlightBytes;        // Bytes sent but not yet acknowledged

    // Error codes
    private Long resetErrorCode;
    private Long stopSendingErrorCode;

    public StreamState(long streamId, boolean isServerInitiated, QuicConnectionControl.StreamType streamType,
                      long initialMaxStreamDataToSend, long initialMaxStreamToReceive) {
        this.streamId = streamId;
        this.isServerInitiated = isServerInitiated;
        this.streamType = streamType;
        this.state = State.OPEN;
        this.maxStreamData = initialMaxStreamDataToSend;
        this.remoteMaxStreamData = initialMaxStreamToReceive;
        this.sentBytes = 0;
        this.maxOffset = 0;
        this.inFlightBytes = 0;
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
        return maxStreamData;
    }

    public void setMaxStreamData(long maxStreamData) {
        this.maxStreamData = maxStreamData;
    }

    public long getRemoteMaxStreamData() {
        return remoteMaxStreamData;
    }

    public void setRemoteMaxStreamData(long remoteMaxStreamData) {
        this.remoteMaxStreamData = remoteMaxStreamData;
    }

    public long getSentBytes() {
        return sentBytes;
    }

    public void addSentBytes(long bytes) {
        this.sentBytes += bytes;
        this.inFlightBytes += bytes;
    }

    public long getMaxOffset() {
        return maxOffset;
    }

    public long updateMaxOffset(long offset) {
        long prevOffset = maxOffset;
        maxOffset = Math.max(maxOffset, offset);
        return maxOffset - prevOffset;
    }

    public long getInFlightBytes() {
        return inFlightBytes;
    }

    public void onBytesAcknowledged(long bytes) {
        this.inFlightBytes = Math.max(0, this.inFlightBytes - bytes);
    }

    public boolean isFlowControlBlocked() {
        // Check if sending more data would exceed peer's limit
        return inFlightBytes >= maxStreamData;
    }

    public boolean canSendBytes(long bytes) {
        // Check if we can send 'bytes' without exceeding peer's limit
        return (inFlightBytes + bytes) <= maxStreamData;
    }

    public void setResetErrorCode(Long resetErrorCode) {
        this.resetErrorCode = resetErrorCode;
    }

    public void setStopSendingErrorCode(Long stopSendingErrorCode) {
        this.stopSendingErrorCode = stopSendingErrorCode;
    }
}

