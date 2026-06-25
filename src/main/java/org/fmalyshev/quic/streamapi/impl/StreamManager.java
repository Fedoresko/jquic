package org.fmalyshev.quic.streamapi.impl;

import org.fmalyshev.quic.QuicConnection;
import org.fmalyshev.quic.streamapi.QuicApplicationProtocol;
import org.fmalyshev.quic.streamapi.QuicApplicationProtocolConnectionHandler;
import org.fmalyshev.quic.streamapi.QuicStreamException;
import org.fmalyshev.quic.streamapi.QuicStreamResponse;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.Consumer;

/**
 * Manages all streams for a single QUIC connection.
 * Handles stream lifecycle, frame processing, and flow control.
 * Thread-safety: ALL methods are called from worker thread only - no synchronization needed.
 */
public class StreamManager {
    public static final int STREAM_FRAME_HEADER_MAX_LEN = 1 + 8 + 8 + 8;
    private static final Logger logger = LoggerFactory.getLogger(StreamManager.class);

    private final QuicConnection connection;
    private final QuicApplicationProtocolConnectionHandler handler;

    // Stream management
    private final Map<Long, StreamState> streams = new HashMap<>();
    private final Map<Long, StreamBuffer> streamBuffers = new HashMap<>();

    record FrameRecord (long streamId, boolean fin, ByteBuffer data) {};
    private final Deque<FrameRecord> outbox = new ArrayDeque<>();

    // Stream limits
    private final int maxBidirectionalStreams;
    private final int maxUnidirectionalStreams;
    private final int maxStreamData;
    private final int maxData;

    // Connection-level flow control - receiving side
    private long totalReceivedBytes = 0;

    // Connection-level flow control - sending side (in-flight bytes)
    private long totalInFlightBytes = 0;

    // Stream counters - server always uses odd stream IDs
    private long nextServerBidiStreamId = 1;
    private long nextServerUniStreamId = 3;

    public StreamManager(QuicConnection connection,
                        QuicApplicationProtocolConnectionHandler handler,
                        QuicApplicationProtocol protocol) {
        this.connection = connection;
        this.handler = handler;
        this.maxBidirectionalStreams = protocol.getMaxBidirectionalStreamsPerConnection();
        this.maxUnidirectionalStreams = protocol.getMaxUnidirectionalStreamsPerConnection();
        this.maxStreamData = protocol.getMaxStreamData();
        this.maxData = protocol.getMaxData();
    }

    /**
     * Opens a new stream.
     * This is always server-initiated (stream IDs are odd).
     */
    public long openStream(QuicStreamResponse.StreamType streamType) throws QuicStreamException {
        long streamId;
        if (streamType == QuicStreamResponse.StreamType.Bidirectional) {
            streamId = nextServerBidiStreamId;
            nextServerBidiStreamId += 4;
        } else {
            streamId = nextServerUniStreamId;
            nextServerUniStreamId += 4;
        }

        // Check stream limits
        int currentCount = (int) streams.values().stream()
            .filter(s -> s.getStreamType() == streamType && s.isServerInitiated())
            .count();

        int limit = streamType == QuicStreamResponse.StreamType.Bidirectional ?
                   maxBidirectionalStreams : maxUnidirectionalStreams;

        if (currentCount >= limit) {
            throw new QuicStreamException("Stream limit reached for " + streamType);
        }

        // Create stream state
        StreamState state = new StreamState(streamId, true, streamType, maxStreamData);
        streams.put(streamId, state);
        StreamBuffer buffer = new StreamBuffer(streamId, maxStreamData);
        streamBuffers.put(streamId, buffer);

        // Note: Handler callback will be called when worker thread processes first frame
        // or when explicitly allocated by application

        logger.debug("Opened new stream {} (type: {}, server: true)", streamId, streamType);
        return streamId;
    }

    /**
     * Processes a frame. Called by worker thread only.
     */
    public boolean processFrame(StreamFrameProcessor.StreamFrame frame) throws IOException, QuicStreamException {
        FrameRecord record;
        while ((record = outbox.poll()) != null) {
            if (!trySendData(record.streamId, record.fin, record.data, streams.get(record.streamId))) {
                logger.info("Pending answers still cannot be send, stop processing new frames CID {}", connection.getConnectionId());
                outbox.push(record);
                return false;
            }
        }

        // Route based on frame type and decode using StreamFrameProcessor
        if (frame instanceof StreamFrameProcessor.StreamFrameData) {
            handleFrame((StreamFrameProcessor.StreamFrameData) frame);
        } else if (frame instanceof StreamFrameProcessor.ResetStreamFrameData) {
            handleFrame((StreamFrameProcessor.ResetStreamFrameData) frame);
        } else if (frame instanceof StreamFrameProcessor.StopSendingFrameData) {
            handleFrame((StreamFrameProcessor.StopSendingFrameData) frame);
        } else if (frame instanceof StreamFrameProcessor.MaxStreamDataFrameData) {
            handleFrame((StreamFrameProcessor.MaxStreamDataFrameData) frame);
        } else if (frame instanceof StreamFrameProcessor.MaxStreamsFrameData) {
            handleFrame((StreamFrameProcessor.MaxStreamsFrameData) frame);
        } else if (frame instanceof StreamFrameProcessor.StreamDataBlockedFrameData) {
            handleFrame((StreamFrameProcessor.StreamDataBlockedFrameData) frame);
        } else if (frame instanceof StreamFrameProcessor.StreamsBlockedFrameData) {
            handleFrame((StreamFrameProcessor.StreamsBlockedFrameData) frame);
        }

        return true;
    }

    private void handleFrame(StreamFrameProcessor.StreamFrameData frame) throws IOException {
        long streamId = frame.streamId;
        long offset = frame.offset;
        ByteBuffer data = frame.data;
        boolean hasFin = frame.fin;

        // Ensure stream and buffer exist
        StreamState state = streams.computeIfAbsent(streamId, id -> {
            boolean serverInitiated = (id & 0x01) == 1;
            QuicStreamResponse.StreamType type = (id & 0x02) == 0 ? 
                QuicStreamResponse.StreamType.Bidirectional : 
                QuicStreamResponse.StreamType.Unidirectional;

            StreamState newState = new StreamState(id, serverInitiated, type, maxStreamData);
            streamBuffers.put(id, new StreamBuffer(id, maxStreamData));
            return newState;
        });

        StreamBuffer streamBuffer = streamBuffers.get(streamId);
        if (streamBuffer == null) {
            logger.warn("Stream buffer not found for stream {}", streamId);
            return;
        }

        // Check if this is a new stream (first data)
        boolean isNewStream = state.getReceivedBytes() == 0;

        if (!state.canReceive()) {
            logger.warn("Received STREAM frame on stream {} in state {}", streamId, state.getState());
            return;
        }

        // Notify handler for new stream
        if (isNewStream) {
            QuicStreamResponseImpl response = new QuicStreamResponseImpl(this);
            handler.onNewStreamAllocated(streamId, response, state.isServerInitiated(), state.getStreamType());
        }

        // Add data to reassembly buffer - StreamBuffer enforces maxStreamData limit
        if (streamBuffer.addIncomingData(offset, data, hasFin)) {
            // Deliver contiguous data to handler
            deliverStreamData(streamId, null);
        }

        // Update state
        state.addReceivedBytes(data.remaining());
        if (hasFin) {
            if (state.getState() == StreamState.State.OPEN) {
                state.setState(StreamState.State.HALF_CLOSED_REMOTE);
            } else if (state.getState() == StreamState.State.HALF_CLOSED_LOCAL) {
                state.setState(StreamState.State.CLOSED);
            }
        }

        // Send MAX_STREAM_DATA if needed
        if (shouldSendMaxStreamData(state)) {
            sendMaxStreamDataFrame(streamId, state.getRemoteMaxStreamData() * 2);
        }
    }

    private void handleFrame(StreamFrameProcessor.ResetStreamFrameData frame) throws IOException {
        long streamId = frame.streamId;
        long errorCode = frame.errorCode;
        long finalSize = frame.finalSize;

        StreamState state = streams.get(streamId);
        if (state == null) {
            logger.warn("Received RESET_STREAM for unknown stream {}", streamId);
            return;
        }

        state.setState(StreamState.State.RESET_RECEIVED);
        state.setResetErrorCode(errorCode);

        // Deliver any buffered data with error code
        deliverStreamData(streamId, errorCode);

        logger.info("Stream {} reset by peer with error code {}", streamId, errorCode);
    }

    private void handleFrame(StreamFrameProcessor.StopSendingFrameData frame) {
        long streamId = frame.streamId;
        long errorCode = frame.errorCode;

        StreamState state = streams.get(streamId);
        if (state == null) {
            logger.warn("Received STOP_SENDING for unknown stream {}", streamId);
            return;
        }

        state.setStopSendingErrorCode(errorCode);

        // Send RESET_STREAM in response
        sendResetStreamFrame(streamId, errorCode, state.getSentBytes());

        logger.info("Received STOP_SENDING for stream {} with error code {}", streamId, errorCode);
    }

    private void handleFrame(StreamFrameProcessor.MaxStreamDataFrameData frame) {
        long streamId = frame.streamId;
        long maximumData = frame.maximumData;

        StreamState state = streams.get(streamId);
        if (state != null) {
            state.setMaxStreamData(maximumData);
            logger.debug("Updated MAX_STREAM_DATA for stream {} to {}", streamId, maximumData);
        }
    }

    private void handleFrame(StreamFrameProcessor.MaxStreamsFrameData frame) {
        long maximumStreams = frame.maximumStreams;
        logger.debug("Updated MAX_STREAMS ({}) to {}", 
                    frame.bidirectional ? "bidi" : "uni", maximumStreams);
    }

    private void handleFrame(StreamFrameProcessor.StreamDataBlockedFrameData frame) {
        long streamId = frame.streamId;
        long limit = frame.limit;
        logger.debug("Peer is blocked on stream {} at limit {}", streamId, limit);
        // Could send MAX_STREAM_DATA to unblock
        sendMaxStreamDataFrame(streamId, limit * 2);
    }

    private void handleFrame(StreamFrameProcessor.StreamsBlockedFrameData frame) {
        long limit = frame.limit;
        logger.debug("Peer is blocked on {} streams at limit {}", 
                    frame.bidirectional ? "bidi" : "uni", limit);
    }

    /**
     * Sends data on a stream immediately.
     * Called from worker thread (via QuicStreamResponse).
     * 
     * @return true if data was sent, false if blocked by flow control (backpressure)
     */
    public void sendData(long streamId, Consumer<ByteBuffer> writer, boolean fin) throws QuicStreamException {
        StreamState state = streams.get(streamId);
        if (state == null) {
            throw new QuicStreamException("Stream " + streamId + " does not exist");
        }
        if (!state.canSend()) {
            throw new QuicStreamException("Stream " + streamId + " cannot send data in state " + state.getState());
        }

        ByteBuffer data = ByteBuffer.allocate(1024);
        data.position(STREAM_FRAME_HEADER_MAX_LEN);
        ByteBuffer slice = data.slice();
        writer.accept(slice);
        data.limit(slice.limit() + STREAM_FRAME_HEADER_MAX_LEN);

        if (!trySendData(streamId, fin, data, state) ) {
            outbox.add(new FrameRecord(streamId, fin, data));
        }
    }

    private boolean trySendData(long streamId, boolean fin, ByteBuffer data, StreamState state) throws QuicStreamException {
        int dataSize = data.remaining();
        if (totalInFlightBytes + dataSize > maxData) {
            logger.debug("Connection {} blocked by MAX_DATA: in-flight={}, data={}, limit={}",
                        connection.getConnectionId(), totalInFlightBytes, dataSize, maxData);
            // Send DATA_BLOCKED frame to inform peer
            sendDataBlockedFrame(maxData);
            return false;
        }

        // Check stream-level flow control (in-flight bytes vs MAX_STREAM_DATA)
        if (!state.canSendBytes(dataSize)) {
            logger.debug("Stream {} blocked by MAX_STREAM_DATA: in-flight={}, data={}, limit={}",
                    streamId, state.getInFlightBytes(), dataSize, state.getMaxStreamData());
            sendStreamDataBlockedFrame(streamId, state.getMaxStreamData());
            return false;
        }

        // Get send offset
        StreamBuffer buffer = streamBuffers.get(streamId);
        if (buffer == null) {
            throw new QuicStreamException("Stream buffer not found for stream " + streamId);
        }
        long offset = buffer.allocateSendOffset(dataSize);

        // Encode and send frame immediately
        ByteBuffer encodedFrame = StreamFrameProcessor.encodeStreamFrame(
                streamId, offset, data, fin);

        byte[] tt = new byte[encodedFrame.remaining()];
        encodedFrame.duplicate().get(tt);
        logger.debug("Sending STREAM resp {}", HexFormat.of().formatHex(tt));

        try {
            connection.send1RttPacket(encodedFrame);

            // Update in-flight counters
            state.addSentBytes(dataSize); // Also updates stream in-flight
            totalInFlightBytes += dataSize;

            logger.debug("Sent {} bytes on stream {}: conn in-flight={}/{}, stream in-flight={}/{}",
                    dataSize, streamId, totalInFlightBytes, maxData,
                    state.getInFlightBytes(), state.getMaxStreamData());
        } catch (Exception e) {
            throw new QuicStreamException("Failed to send STREAM frame: " + e.getMessage());
        }

        // Update state
        if (fin) {
            if (state.getState() == StreamState.State.OPEN) {
                state.setState(StreamState.State.HALF_CLOSED_LOCAL);
            } else if (state.getState() == StreamState.State.HALF_CLOSED_REMOTE) {
                state.setState(StreamState.State.CLOSED);
            }
        }

        return true;
    }

    /**
     * Closes a stream by sending STOP_SENDING.
     */
    public void closeStream(long streamId, long errorCode) throws QuicStreamException {
        StreamState state = streams.get(streamId);
        if (state == null) {
            throw new QuicStreamException("Stream " + streamId + " does not exist");
        }

        sendStopSendingFrame(streamId, errorCode);
    }

    /**
     * Delivers stream data to handler. MUST be called from worker thread only.
     */
    private void deliverStreamData(long streamId, @Nullable Long errorCode) throws IOException {
        StreamBuffer buffer = streamBuffers.get(streamId);
        if (buffer == null) return;

        StreamBuffer.StreamData data = buffer.readAvailableData();
        if (data != null) {
            QuicStreamResponseImpl response = new QuicStreamResponseImpl(this);
            handler.onStreamDataReceived(streamId, response, data.getData(), data.isLast(), errorCode);
        }
    }

    private boolean shouldSendMaxStreamData(StreamState state) {
        long received = state.getReceivedBytes();
        long limit = state.getRemoteMaxStreamData();
        return received > limit / 2; // Send update at 50% threshold
    }

    private void sendMaxStreamDataFrame(long streamId, long maximumData) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeMaxStreamDataFrame(streamId, maximumData);
        try {
            connection.send1RttPacket(frame);
            StreamState state = streams.get(streamId);
            if (state != null) {
                state.setRemoteMaxStreamData(maximumData);
            }
        } catch (Exception e) {
            logger.error("Failed to send MAX_STREAM_DATA frame", e);
        }
    }

    private void sendResetStreamFrame(long streamId, long errorCode, long finalSize) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeResetStreamFrame(streamId, errorCode, finalSize);
        try {
            connection.send1RttPacket(frame);
            StreamState state = streams.get(streamId);
            if (state != null) {
                state.setState(StreamState.State.RESET_SENT);
            }
        } catch (Exception e) {
            logger.error("Failed to send RESET_STREAM frame", e);
        }
    }

    private void sendStopSendingFrame(long streamId, long errorCode) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeStopSendingFrame(streamId, errorCode);
        try {
            connection.send1RttPacket(frame);
        } catch (Exception e) {
            logger.error("Failed to send STOP_SENDING frame", e);
        }
    }

    private void sendStreamDataBlockedFrame(long streamId, long limit) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeStreamDataBlockedFrame(streamId, limit);
        try {
            connection.send1RttPacket(frame);
        } catch (Exception e) {
            logger.error("Failed to send STREAM_DATA_BLOCKED frame", e);
        }
    }

    public long getTotalReceivedBytes() {
        return totalReceivedBytes;
    }

    public int getMaxData() {
        return maxData;
    }

    public void addReceivedBytes(int bytes) {
        totalReceivedBytes += bytes;
    }

    /**
     * Called when a packet is acknowledged (from worker thread).
     * Parses STREAM frames from the unencrypted payload and updates flow control.
     */
    public void onAckReceived(long streamId, long dataLength) {
        // Update stream flow control
        StreamState state = streams.get(streamId);
        if (state != null) {
            state.onBytesAcknowledged(dataLength);
            totalInFlightBytes -= dataLength;

            logger.debug("Packet ACKed: stream {} {} bytes acknowledged, stream in-flight={}, conn in-flight={}",
                       streamId, dataLength, state.getInFlightBytes(), totalInFlightBytes);
        }
    }

    /**
     * Sends DATA_BLOCKED frame to inform peer we're blocked at connection level.
     */
    private void sendDataBlockedFrame(long limit) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeDataBlockedFrame(limit);
        try {
            connection.send1RttPacket(frame);
            logger.debug("Sent DATA_BLOCKED frame: limit={}", limit);
        } catch (Exception e) {
            logger.error("Failed to send DATA_BLOCKED frame", e);
        }
    }

    /**
     * Implementation of QuicStreamResponse for this manager.
     */
    private static class QuicStreamResponseImpl implements QuicStreamResponse {
        private final StreamManager manager;

        public QuicStreamResponseImpl(StreamManager manager) {
            this.manager = manager;
        }

        @Override
        public void closeConnection(long errorCode, String reason) throws QuicStreamException {
            // TODO: Implement connection close via QuicConnection
        }

        @Override
        public void openStream(StreamType streamType) throws QuicStreamException {
            manager.openStream(streamType);
        }

        @Override
        public void closeStream(long streamId, long errorCode) throws QuicStreamException {
            manager.closeStream(streamId, errorCode);
        }

        @Override
        public void sendData(long streamId, Consumer<ByteBuffer> writer, boolean fin) throws QuicStreamException {
            manager.sendData(streamId, writer, fin);
        }
    }
}
