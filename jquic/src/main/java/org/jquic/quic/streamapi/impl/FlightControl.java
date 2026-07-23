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

import org.jquic.quic.ConnectionMetadata.InitialStreamLimits;
import org.jquic.quic.QuicTransportError;
import org.jquic.quic.streamapi.QuicStreamException;
import org.jquic.quic.streamapi.QuicConnectionControl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

import static org.jquic.quic.QuicTransportError.FLOW_CONTROL_ERROR;
import static org.jquic.quic.QuicTransportError.STREAM_STATE_ERROR;
import static org.jquic.quic.streamapi.QuicConnectionControl.StreamType.Bidirectional;
import static org.jquic.quic.streamapi.QuicConnectionControl.StreamType.Unidirectional;
import static org.jquic.quic.streamapi.impl.StreamState.State.CLOSED;

class FlightControl {
    private static final Logger logger = LoggerFactory.getLogger(FlightControl.class);
    
    private final Map<Long, StreamState> streams = new HashMap<>();

    final int maxStreamDataCap;
    private final long maxDataCap; // Hard limit per connection
    private long currentMaxData; // Current MAX_DATA value advertised to peer
    // Stream limits
    private final int maxBidirectionalStreams;
    private final int maxUnidirectionalStreams;
    // Connection-level flow control - receiving side
    private long totalMaxOffsetsSum = 0;
    private long totalBufferedBytes = 0; // Total bytes currently stored in all stream buffers
    // Connection-level flow control - sending side (in-flight bytes)
    private long totalInFlightBytes = 0;
    private final StreamManager streamManager;

    private long bidirectionalOutgoingStreamCap;
    private long unidirectionalOutgoingStreamCap;
    private long bidirectionalIncomingStreamCap;
    private long unidirectionalIncomingStreamCap;

    private long currentIncomingBidiStreamsCount = 0;
    private long currentIncomingUniStreamsCount = 0;
    private long maxIncomingBidiStream = 0;
    private long maxIncomingUniStream = 0;

    private final InitialStreamLimits serverInitialLimits;
    private final InitialStreamLimits clientInitialLimits;

    /**
     * Accepts protocol negotiated flight limits
     * @param streamManager - needed to send responses \ close connections according to flight-control QUIC specs
     */
    FlightControl(InitialStreamLimits serverLimits, InitialStreamLimits clientLimits, StreamManager streamManager) {
        serverInitialLimits = serverLimits;
        clientInitialLimits = clientLimits;
        this.maxStreamDataCap = serverLimits.maxStreamDataUni;
        this.maxDataCap = serverLimits.maxData;
        this.currentMaxData = clientInitialLimits.maxData; // Initial value
        this.maxBidirectionalStreams = serverLimits.maxBidi; // Our capacity same as the initial value
        this.maxUnidirectionalStreams = serverLimits.maxUni;
        this.streamManager = streamManager;

        //defaults
        bidirectionalIncomingStreamCap = serverLimits.maxBidi * 4;
        unidirectionalIncomingStreamCap = 2 + serverLimits.maxUni * 4;
        
        // If peer provided initial_max_streams, use it
        bidirectionalOutgoingStreamCap = 1 + clientLimits.maxBidi * 4;
        unidirectionalOutgoingStreamCap = 3 + clientLimits.maxUni * 4;
    }

    /**
     * Counterparty has acknowledged a stream packet, needed for counting total unacked data.
     * @param ackTotalLength - acked payload size
     */
    public void bytesAcked(long streamId, Long ackTotalLength) {
        StreamState state = streams.get(streamId);
        if (state != null) {
            state.onBytesAcknowledged(ackTotalLength);
        }
        totalInFlightBytes -= ackTotalLength;
    }

    /**
     * Data buffered for a particular stream was processed, needed to count buffered data
     * This method should update local stream byte counts and send max_data / max_stream_data frames.
     * @param freedBytes - size of payload
     */
    public void byfferedBytesFreed(long streamId, long freedBytes) {
        totalBufferedBytes -= freedBytes;
        updateMaxDataIfNeeded(streamId);
    }

    public long getTotalInFlightBytes() {
        return totalInFlightBytes;
    }

    /**
     * Called when a stream receives some new data, and it is written to buffer
     * @param dataSize - payload size
     * @param bufferedBytes - already buffered to the stream
     */
    public void addReceivedBytes(long streamId, long offset, int dataSize, long bufferedBytes) {
        totalBufferedBytes += dataSize;
        StreamState streamState = streams.get(streamId);
        long delta = streamState.updateMaxOffset(offset + dataSize);
        totalMaxOffsetsSum += delta;

        long received = streamState.getMaxOffset();
        long limit = streamState.getRemoteMaxStreamData();
        long freeQueue = StreamManager.STREAM_BUFFER_CAPACITY - bufferedBytes;
        // Send MAX_STREAM_DATA if needed
        if (received + freeQueue / 2 > limit) {
            streamManager.sendMaxStreamDataFrame(streamId, received + freeQueue);
            streamState.setRemoteMaxStreamData(received + freeQueue);
        }

        logger.debug("Received {} bytes of offset {} for stream {}, new max offset {} new totoal max offset sum {}", dataSize, offset, streamId, streamState.getMaxOffset(), totalMaxOffsetsSum);
    }

    /**
     * Tests the stream caps (max_stream_data, max_data) inbound.
     * Could close the connection in case of protocol violations.
     * @param dataSize - payload size
     * @return true if caps are satisfied
     */
    public boolean isReceiveCapReached(long streamId, long offset, int dataSize) {
        StreamState streamState = streams.get(streamId);
        long maxOffset = streamState.getMaxOffset();
        long delta = offset + dataSize - maxOffset;

        if (offset + dataSize > streamState.getRemoteMaxStreamData()) {
            streamManager.sendConnectionClose(FLOW_CONTROL_ERROR, "MAX_STREAM_DATA limit reached");
            return true;
        }
        if (totalMaxOffsetsSum + delta > currentMaxData) {
            logger.debug("Connection: would exceed maxData ({} + {} > {})",
                    totalMaxOffsetsSum, delta, currentMaxData);

            streamManager.sendConnectionClose(FLOW_CONTROL_ERROR, "MAX_DATA limit reached");
            return true;
        }
        return false;
    }

    /**
     * Tests the stream caps (max_stream_data, max_data) outbound.
     * Could send stream_blocked according to QUIC spec.
     * @param dataSize - payload size
     * @return true is caps are satisfied.
     */
    public boolean canSend(long streamId, int dataSize) {
        StreamState state = streams.get(streamId);
        if (!state.canSendBytes(dataSize)) {
            logger.warn("Stream {} blocked by MAX_STREAM_DATA: in-flight={}, data={}, limit={}",
                    streamId, state.getInFlightBytes(), dataSize, state.getMaxStreamData());
            streamManager.sendStreamDataBlockedFrame(streamId, state.getMaxStreamData());
            return false;
        }
        if (!canSendMoreConnectionData(dataSize)) {
            logger.warn("Connection blocked by MAX_DATA: in-flight={}, data={}, limit={}",
                    totalInFlightBytes, dataSize, currentMaxData);
            // Send DATA_BLOCKED frame to inform peer
            streamManager.sendDataBlockedFrame(currentMaxData, streamId);
            return false;
        }
        return true;
    }

    public boolean canSendMoreConnectionData(int dataSize) {
        return totalInFlightBytes + dataSize <= currentMaxData;
    }

    // Update current max data counts, send max_data \ max_stream_data frames when needed.
    private void updateMaxDataIfNeeded(long streamId) {
        // New MAX_DATA = hardCapacity - bufferedBytes + totalReceived
        long newMaxData = maxDataCap - totalBufferedBytes + totalMaxOffsetsSum;

        // Send MAX_DATA if the increase is significant
        if (currentMaxData - totalMaxOffsetsSum < (maxDataCap - totalBufferedBytes) / 2) {
            logger.debug("Current maxData {} totalReceivedBytes {} maxDataCap {} totalBufferedBytes {}", currentMaxData, totalMaxOffsetsSum, maxDataCap, totalBufferedBytes);
            streamManager.sendMaxDataFrame(newMaxData, streamId);
            currentMaxData = newMaxData;
        }
    }

    /**
     * Server requests to open a new stream
     * @param streamType - bidirectional/unidirectional
     */
    public void openOutgoingStream(long streamId, QuicConnectionControl.StreamType streamType) throws QuicStreamException {
        long limit = streamType == Bidirectional ?
                bidirectionalOutgoingStreamCap : unidirectionalOutgoingStreamCap;

        if (streamId >= limit) {
            throw new QuicStreamException("Stream limit reached for " + streamType);
        }

        StreamState state = new StreamState(streamId, true, streamType,
            streamType == Bidirectional ? serverInitialLimits.maxStreamDataBidiLocal : serverInitialLimits.maxStreamDataUni,
            streamType == Bidirectional ? clientInitialLimits.maxStreamDataBidiRemote : clientInitialLimits.maxStreamDataUni);
        streams.put(streamId, state);
    }

    /**
     * Stream FIN flag was received (or send)
     * @param local - if TRUE than it was outbound FIN, inbound in another case.
     */
    public void onStreamFin(long streamId, boolean local) {
        StreamState streamState = streams.get(streamId);
        StreamState.State prevState = streamState.getState();
        if (local) {
            if (streamState.getState() == StreamState.State.OPEN) {
                streamState.setState(StreamState.State.HALF_CLOSED_LOCAL);
            } else if (streamState.getState() == StreamState.State.HALF_CLOSED_REMOTE) {
                streamState.setState(CLOSED);
            }
        } else {
            if (streamState.getState() == StreamState.State.OPEN) {
                decrementActiveStreamCount(streamId);
                streamState.setState(StreamState.State.HALF_CLOSED_REMOTE);
            } else if (streamState.getState() == StreamState.State.HALF_CLOSED_LOCAL) {
                decrementActiveStreamCount(streamId);
                streamState.setState(CLOSED);
            }
        }

        if (prevState != CLOSED && streamState.getState() == CLOSED) {
            streams.remove(streamId);
        }
    }

    private void decrementActiveStreamCount(long streamId) {
        if ((streamId & 0x01) == 0) { // client initiated
            QuicConnectionControl.StreamType type = StreamManager.getStreamType(streamId);
            if (type == Bidirectional) {
                currentIncomingBidiStreamsCount--;
            } else {
                currentIncomingUniStreamsCount--;
            }
        }
    }

    /**
     * Stream data received. Either a new stream or some existing one.
     * @return state object
     */
    public StreamState.State incomingStream(long streamId) {
        if (streamId % 2 != 0) { //not incoming stream
            streamManager.sendConnectionClose(STREAM_STATE_ERROR, "Wrong incoming stream id "+streamId);
            return CLOSED;
        }

        QuicConnectionControl.StreamType type = StreamManager.getStreamType(streamId);
        boolean isBidi = type == Bidirectional;
        long cap = isBidi ? bidirectionalIncomingStreamCap : unidirectionalIncomingStreamCap;

        if (streamId >= cap) {
            logger.debug("Stream limit reached for stream {}: cap is {}", streamId, cap);
            streamManager.sendConnectionClose(QuicTransportError.STREAM_LIMIT_ERROR, "MAX_STREAM_CAP");
            return CLOSED;
        }

        boolean isNew = !streams.containsKey(streamId);
        StreamState state = streams.computeIfAbsent(streamId, id -> new StreamState(id, false, type,
                isBidi ? serverInitialLimits.maxStreamDataBidiRemote : serverInitialLimits.maxStreamDataUni,
                isBidi ? clientInitialLimits.maxStreamDataBidiLocal : clientInitialLimits.maxStreamDataUni));

        if (isNew) {
            long streamIndex = streamId / 4;
            if (isBidi) {
                maxIncomingBidiStream = streamIndex;
                currentIncomingBidiStreamsCount++;
                long maxStreams = bidirectionalIncomingStreamCap / 4;
                if (streamIndex >= maxStreams - maxBidirectionalStreams / 2) {
                    long newMaxStreams = maxStreams - currentIncomingBidiStreamsCount + maxBidirectionalStreams;
                    logger.debug("Sending bidirectional MAX_STREAMS frame because stream index {} exceeds threshold {} new value would be {}", streamIndex, maxStreams - maxBidirectionalStreams / 2, newMaxStreams);
                    bidirectionalIncomingStreamCap = newMaxStreams * 4;
                    streamManager.sendMaxStreamsFrame(newMaxStreams, true);
                }
            } else {
                maxIncomingUniStream = streamIndex;
                currentIncomingUniStreamsCount++;
                long maxStreams = (unidirectionalIncomingStreamCap - 2) / 4;
                if (streamIndex >= maxStreams - maxUnidirectionalStreams / 2) {
                    long newMaxStreams = maxStreams - currentIncomingUniStreamsCount + maxUnidirectionalStreams;
                    logger.debug("Sending unidirectional MAX_STREAMS frame because stream index {} exceeds threshold {} new value would be {}", streamIndex, maxStreams - maxUnidirectionalStreams / 2, newMaxStreams);
                    unidirectionalIncomingStreamCap = 2 + newMaxStreams * 4;
                    streamManager.sendMaxStreamsFrame(newMaxStreams, false);
                }
            }
        }

        return state.getState();
    }

    /**
     * Stream reset frame received.
     */
    public void onStreamReset(long streamId, long errorCode, long finalSize) {
        StreamState state = streams.get(streamId);
        logger.warn("Received RESET_STREAM for setram {}", streamId);
        if (state == null) {
            logger.debug("Received RESET_STREAM for unknown stream {}", streamId);
            return;
        }
        if (state.streamType == Unidirectional && (streamId & 0x01) != 0) {
            streamManager.sendConnectionClose(STREAM_STATE_ERROR , "Stream reset cannot be send by receiver");
            return;
        }
        if (finalSize > state.getRemoteMaxStreamData()) {
            streamManager.sendConnectionClose(FLOW_CONTROL_ERROR, "Stream reset final size exceeds stream max data cap");
            return;
        }
        long delta = state.updateMaxOffset(finalSize);
        totalMaxOffsetsSum += delta;
        if (totalMaxOffsetsSum > currentMaxData) {
            streamManager.sendConnectionClose(FLOW_CONTROL_ERROR, "Stream reset final size exceeds max data cap");
            return;
        }

        StreamState.State prevState = state.getState();
        if (state.streamType == Bidirectional) {
            if (prevState == StreamState.State.HALF_CLOSED_LOCAL || prevState == StreamState.State.RESET_ACK_RECEIVED) {
                state.setState(CLOSED);
            } else {
                state.setState(StreamState.State.HALF_CLOSED_REMOTE);
            }
        } else {
            state.setState(CLOSED);
        }

        state.setResetErrorCode(errorCode);

        if (state.getState() == CLOSED && prevState != CLOSED) {
             decrementActiveStreamCount(streamId);
             streams.remove(streamId);
        }
    }

    /**
     *  Stop Sending frame received.
     */
    public void onStreamStopSending(long streamId, long errorCode) {
        logger.info("Received STOP_SENDING for stream {} with error code {}", streamId, errorCode);

        StreamState state = streams.get(streamId);
        if (state == null) {
            logger.debug("Received STOP_SENDING for unknown stream {}", streamId);
            return;
        }

        state.setStopSendingErrorCode(errorCode);

        StreamState.State prevState = state.getState();
        if (state.streamType == Bidirectional) {
            if (prevState == StreamState.State.HALF_CLOSED_REMOTE || prevState == StreamState.State.RESET_ACK_RECEIVED) {
                state.setState(CLOSED);
            } else {
                state.setState(StreamState.State.RESET_SENT);
            }
        } else {
            state.setState(CLOSED);
        }

        // Send RESET_STREAM in response
        streamManager.sendResetStreamFrame(streamId, errorCode, state.getSentBytes());

        if (state.getState() == CLOSED && prevState != CLOSED) {
            decrementActiveStreamCount(streamId);
            streams.remove(streamId);
        }
    }

    /**
     *  MAX_STREAM_DATA frame received.
     */
    public void onStreamMaxData(long streamId, long maximumData) {
        StreamState state = streams.get(streamId);
        if (state != null) {
            state.setMaxStreamData(maximumData);
            logger.debug("Updated MAX_STREAM_DATA for stream {} to {}", streamId, maximumData);
        }
    }

    /**
     *  MAX_DATA frame received.
     */
    public void onMaxData(long maximumData) {
        if (maximumData > this.currentMaxData) {
            this.currentMaxData = maximumData;
            logger.debug("Updated connection MAX_DATA to {}", maximumData);
        }
    }

    /**
     *  MAX_STREAMS frame received.
     */
    public void onMaxStreams(boolean bidirectional, long maximumStreams) {
        if (bidirectional) {
            bidirectionalOutgoingStreamCap = 1 + maximumStreams*4;
        } else {
            unidirectionalOutgoingStreamCap = 3 + maximumStreams*4;
        }
        logger.debug("Updated MAX_STREAMS ({}) to {}",
                bidirectional ? "bidi" : "uni", maximumStreams);
    }

    /**
     * STREAM_DATA_BLOCKED frame received.
     * @param limit - limit received
     * @param bufferedBytes - currently buffered bytes for the stream.
     */
    public void onStreamDataBlocked(long streamId, long limit, long bufferedBytes) {
        logger.warn("Peer is blocked on stream {} at limit {}", streamId, limit);
        // Could send MAX_STREAM_DATA to unblock
        StreamState streamState = streams.get(streamId);
        long received = streamState.getMaxOffset();
        long freeQueue = StreamManager.STREAM_BUFFER_CAPACITY - bufferedBytes;
        streamManager.sendMaxStreamDataFrame(streamId, received + freeQueue);
        streamState.setRemoteMaxStreamData(received + freeQueue);
    }

    /**
     * Stream data sent into a stream. Used to update byte counts.
     * @param dataSize - payload size
     */
    public void addSentBytes(long streamId, int dataSize) {
        StreamState state = streams.get(streamId);
        state.addSentBytes(dataSize); // Also updates stream in-flight
        totalInFlightBytes += dataSize;
        logger.debug("Add sent {} bytes for stream {} now it has {} and total sent {}", dataSize, streamId, state.getSentBytes(), totalInFlightBytes);
    }

    /**
     * User code has requested closing stream with an error.
     */
    public void closeStream(long streamId, long errorCode) {
        QuicConnectionControl.StreamType streamType = StreamManager.getStreamType(streamId);
        StreamState streamState = streams.get(streamId);
        if (streamType == Bidirectional) {
            streamState.setState(StreamState.State.RESET_SENT);
            streamManager.sendResetStreamFrame(streamId, errorCode, streamState.getSentBytes());
            streamManager.sendStopSendingFrame(streamId, errorCode);
        }
        else {
            if ((streamId & 0x01) == 0) {
                streamManager.sendStopSendingFrame(streamId, errorCode);
            } else {
                streamState.setState(StreamState.State.RESET_SENT);
                streamManager.sendResetStreamFrame(streamId, errorCode, streamState.getSentBytes());
            }
        }
    }

    /**
     * Check if stream in a state for sending data.
     */
    public boolean isStreamOpenForSend(long streamId) {
        StreamState streamState = streams.get(streamId);
        return streamState != null && streamState.getState().canSend();
    }

    public void onStreamResetAck(long streamId) {
        QuicConnectionControl.StreamType streamType = StreamManager.getStreamType(streamId);
        StreamState streamState = streams.get(streamId);
        if (streamState.getState() != StreamState.State.RESET_SENT) {
            logger.warn("Received ack for STREAM_RESET in state {} for stream {}", streamState.getState(), streamId);
        }
        streamState.setState(StreamState.State.RESET_ACK_RECEIVED);
        decrementActiveStreamCount(streamId);
        streams.remove(streamId);
    }

}

