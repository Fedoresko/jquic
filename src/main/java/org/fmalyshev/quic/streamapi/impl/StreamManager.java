package org.fmalyshev.quic.streamapi.impl;

import org.fmalyshev.quic.*;
import org.fmalyshev.quic.buffers.ChunkedOutputStreamWithAmendmentsImpl;
import org.fmalyshev.quic.buffers.PoolBuffer;
import org.fmalyshev.quic.streamapi.*;
import org.fmalyshev.quic.streamapi.frames.*;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.Consumer;

/**
 * Manages all streams for a single QUIC connection.
 * Handles stream lifecycle, frame processing, and flow control.
 * Stream manager is bound to a particular Worker thread in which all user requests are processed.
 * Thread-safety: ALL methods except {#onStreamFrame} and {#onPacketAcknowledged} are called from
 * worker thread only - no synchronization needed.
 */
public class StreamManager implements ConnectionStreamManager {
    public static final int STREAM_FRAME_HEADER_MAX_LEN = 1 + 8 + 8 + 8;
    private static final Logger logger = LoggerFactory.getLogger(StreamManager.class);
    public static final int STREAM_BUFFER_CAPACITY = 50_000;

    private final QuicConnection connection;
    private final QuicApplicationProtocolConnectionHandler handler;

    // Stream management
    private final Map<Long, StreamState> streams = new HashMap<>();
    private final Map<Long, StreamBuffer> streamBuffers = new HashMap<>();
    private final StreamWorker streamWorker;

    record FrameRecord (long streamId, boolean fin, ByteBuffer data) {};
    private final Deque<FrameRecord> outbox = new ArrayDeque<>();

    // Stream limits
    private final int maxBidirectionalStreams;
    private final int maxUnidirectionalStreams;
    private final int maxStreamDataCap;
    private final long maxDataCap; // Hard limit per connection
    private long currentMaxData; // Current MAX_DATA value advertised to peer

    // Connection-level flow control - receiving side
    private long totalReceivedBytes = 0;
    private long totalBufferedBytes = 0; // Total bytes currently stored in all stream buffers

    // Connection-level flow control - sending side (in-flight bytes)
    private long totalInFlightBytes = 0;

    // Stream counters - server always uses odd stream IDs
    private long nextServerBidiStreamId = 1;
    private long nextServerUniStreamId = 3;

    public StreamManager(QuicConnection connection,
                        QuicApplicationProtocolConnectionHandler handler,
                        QuicApplicationProtocol protocol,
                        StreamWorker streamWorker) {
        this.connection = connection;
        this.handler = handler;
        this.maxBidirectionalStreams = protocol.getMaxBidirectionalStreamsPerConnection();
        this.maxUnidirectionalStreams = protocol.getMaxUnidirectionalStreamsPerConnection();
        this.maxStreamDataCap = protocol.getMaxStreamData();
        this.maxDataCap = protocol.getMaxData();
        this.currentMaxData = maxDataCap; // Initial value
        this.streamWorker = streamWorker;
    }

    // Called from Selector thread
    @Override
    public void onStreamFrame(StreamFrame frame) {
        streamWorker.enqueueFrame(this, frame);
    }

    //Called from Selector thread
    @Override
    public void onPacketAcknowledged(long packetNumber, PacketNumberSpace.SentPacket packet) {
        ByteBuffer payload = packet.getUnencryptedPayload().duplicate();
        while (payload.hasRemaining()) {
            byte ackedFrameType = payload.get();
            // Check if this is a STREAM frame (0x08-0x0f)
            if (ackedFrameType >= 0x08 &&  ackedFrameType <= 0x0f) {
                boolean hasLength = (ackedFrameType & 0x02) != 0;
                long streamId = QuicVarint.read(payload);
                long length = (hasLength) ? QuicVarint.read(payload) : payload.remaining();

                streamWorker.enqueueAck(this, streamId, length);
                payload.position(Math.min(payload.limit(), payload.position() + (int) length));
            }
        }
    }

    /**
     * Called from worker thread
     * Opens a new stream.
     * This is always server-initiated (stream IDs are odd).
     */
    public long openStream(QuicStreamResponse.StreamType streamType) throws QuicStreamException {
        if (connection.getState() != QuicConnection.State.ESTABLISHED) {
            throw new QuicStreamException("Connection is in wrong state " + connection.getState());
        }

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
        StreamState state = new StreamState(streamId, true, streamType, maxStreamDataCap);
        streams.put(streamId, state);
        StreamBuffer buffer = new StreamBuffer(streamId, maxStreamDataCap);
        streamBuffers.put(streamId, buffer);

        // Note: Handler callback will be called when worker thread processes first frame
        // or when explicitly allocated by application

        logger.debug("Opened new stream {} (type: {}, server: true)", streamId, streamType);
        return streamId;
    }

    /**
     * Called from Worker thread
     * Processes a frame. Called by worker thread only.
     */
    public boolean processFrame(StreamFrame frame) throws IOException, QuicStreamException {
        FrameRecord record;
        while ((record = outbox.poll()) != null) {
            if (!trySendData(record.streamId, record.fin, record.data, streams.get(record.streamId))) {
                logger.info("Pending answers still cannot be send, stop processing new frames CID {}", connection.getConnectionId());
                outbox.push(record);
                return false;
            }
        }

        // Route based on frame type and decode using StreamFrameProcessor
        if (frame instanceof StreamFrameData) {
            handleFrame((StreamFrameData) frame);
        } else if (frame instanceof ResetStreamFrameData) {
            handleFrame((ResetStreamFrameData) frame);
        } else if (frame instanceof StopSendingFrameData) {
            handleFrame((StopSendingFrameData) frame);
        } else if (frame instanceof MaxStreamDataFrameData) {
            handleFrame((MaxStreamDataFrameData) frame);
        } else if (frame instanceof MaxStreamsFrameData) {
            handleFrame((MaxStreamsFrameData) frame);
        } else if (frame instanceof StreamDataBlockedFrameData) {
            handleFrame((StreamDataBlockedFrameData) frame);
        } else if (frame instanceof StreamsBlockedFrameData) {
            handleFrame((StreamsBlockedFrameData) frame);
        }

        return true;
    }

    /**
     * Called from Worker thread.
     * Process acknowledged stream bytes.
     */
    public void processAck(long streamId, Long ackTotalLength) {
        // Update stream flow control
        StreamState state = streams.get(streamId);
        if (state != null) {
            state.onBytesAcknowledged(ackTotalLength);
            totalInFlightBytes -= ackTotalLength;

            logger.debug("Packet ACKed: stream {} {} bytes acknowledged, stream in-flight={}, conn in-flight={}",
                    streamId, ackTotalLength, state.getInFlightBytes(), totalInFlightBytes);
        }
    }

    private void handleFrame(StreamFrameData frame) throws IOException {
        long streamId = frame.streamId;
        long offset = frame.offset;
        PoolBuffer data = frame.data;
        boolean hasFin = frame.fin;

        // Ensure stream and buffer exist
        StreamState state = streams.computeIfAbsent(streamId, id -> {
            boolean serverInitiated = (id & 0x01) == 1;
            QuicStreamResponse.StreamType type = (id & 0x02) == 0 ? 
                QuicStreamResponse.StreamType.Bidirectional : 
                QuicStreamResponse.StreamType.Unidirectional;

            StreamState newState = new StreamState(id, serverInitiated, type, maxStreamDataCap);
            streamBuffers.put(id, new StreamBuffer(id, maxStreamDataCap));
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
            QuicStreamResponseImpl response = new QuicStreamResponseImpl();
            handler.onNewStreamAllocated(streamId, response, state.isServerInitiated(), state.getStreamType());
        }

        // Update state
        int dataSize = data.buf().remaining();
        if (totalReceivedBytes + dataSize > currentMaxData) {
            // Reject frame - exceeds connection maxData limit
            logger.warn("Rejecting frame for connection {}: would exceed maxData ({} + {} > {})",
                    getConnectionId(), totalReceivedBytes, dataSize, currentMaxData);
            connection.closeConnection(QuicTransportError.FLOW_CONTROL_ERROR, "MAX_DATA limit reached");
            return;
        }

        totalReceivedBytes += dataSize;
        state.addReceivedBytes(dataSize);

        // Add data to reassembly buffer - StreamBuffer enforces maxStreamData limit
        if (streamBuffer.addIncomingData(offset, data, hasFin)) {
            // Update totalBufferedBytes when data is added to buffer
            totalBufferedBytes += dataSize;
            // Deliver contiguous data to handler
            deliverStreamData(streamId, null);
        } else {
            logger.warn("Connection {} stream {} has reached MAX_STREAM_DATA", getConnectionId(), streamId);
            connection.closeConnection(QuicTransportError.FLOW_CONTROL_ERROR, "MAX_STREAM_DATA limit reached");
        }

        if (hasFin) {
            if (state.getState() == StreamState.State.OPEN) {
                state.setState(StreamState.State.HALF_CLOSED_REMOTE);
            } else if (state.getState() == StreamState.State.HALF_CLOSED_LOCAL) {
                state.setState(StreamState.State.CLOSED);
            }
        }

        long received = state.getReceivedBytes();
        long limit = state.getRemoteMaxStreamData();
        long freeQueue = STREAM_BUFFER_CAPACITY - streamBuffer.getBufferedBytes();
        // Send MAX_STREAM_DATA if needed
        if (received + freeQueue / 2 > limit) {
            sendMaxStreamDataFrame(streamId, received + freeQueue);
        }
    }

    private void handleFrame(ResetStreamFrameData frame) throws IOException {
        long streamId = frame.streamId;
        long errorCode = frame.errorCode;

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

    private void handleFrame(StopSendingFrameData frame) {
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

    private void handleFrame(MaxStreamDataFrameData frame) {
        long streamId = frame.streamId;
        long maximumData = frame.maximumData;

        StreamState state = streams.get(streamId);
        if (state != null) {
            state.setMaxStreamData(maximumData);
            logger.debug("Updated MAX_STREAM_DATA for stream {} to {}", streamId, maximumData);
        }
    }

    private void handleFrame(MaxStreamsFrameData frame) {
        long maximumStreams = frame.maximumStreams;
        logger.debug("Updated MAX_STREAMS ({}) to {}", 
                    frame.bidirectional ? "bidi" : "uni", maximumStreams);
    }

    private void handleFrame(StreamDataBlockedFrameData frame) {
        long streamId = frame.streamId;
        long limit = frame.limit;
        logger.debug("Peer is blocked on stream {} at limit {}", streamId, limit);
        // Could send MAX_STREAM_DATA to unblock
        sendMaxStreamDataFrame(streamId, limit * 2);
    }

    private void handleFrame(StreamsBlockedFrameData frame) {
        long limit = frame.limit;
        logger.debug("Peer is blocked on {} streams at limit {}", 
                    frame.bidirectional ? "bidi" : "uni", limit);
    }

    /**
     * Sends data on a stream immediately.
     * Called from worker thread (via QuicStreamResponse).
     */
    public void sendData(long streamId, Consumer<DataOutputStream> writer, boolean fin) throws QuicStreamException  {
        if (connection.getState() != QuicConnection.State.ESTABLISHED) {
            throw new QuicStreamException("Connection is in wrong state " + connection.getState());
        }

        StreamState state = streams.get(streamId);
        if (state == null) {
            throw new QuicStreamException("Stream " + streamId + " does not exist");
        }
        if (!state.canSend()) {
            throw new QuicStreamException("Stream " + streamId + " cannot send data in state " + state.getState());
        }

        ByteBuffer data = ByteBuffer.allocate(2048);
        data.position(STREAM_FRAME_HEADER_MAX_LEN);

        ChunkedOutputStreamWithAmendmentsImpl outs = new ChunkedOutputStreamWithAmendmentsImpl(data,
                (int) connection.tlsMetadata.clientMetadata.maxUdpPayloadSize - 16,
                (buf, off ) -> {
                    int dataSize = buf.remaining();
                    StreamBuffer buffer = streamBuffers.get(streamId);
                    long offset = buffer.allocateSendOffset(dataSize);
                    ByteBuffer encodedFrame = StreamFrameProcessor.encodeStreamFrame(
                            streamId, offset, buf.duplicate(), fin);

                    if (logger.isDebugEnabled()) {
                        byte[] tt = new byte[encodedFrame.remaining()];
                        encodedFrame.duplicate().get(tt);
                        logger.debug("Sending STREAM resp {}", HexFormat.of().formatHex(tt));
                    }
                    int chunkEnd = encodedFrame.limit();
                    buf.limit(buf.capacity());
                    buf.position(chunkEnd + STREAM_FRAME_HEADER_MAX_LEN);
                    return encodedFrame;
                }
        );

        writer.accept(outs);

        try {
            outs.close();
        } catch (IOException e) {
            throw new QuicStreamException("Cant write stream data", e);
        }

        for (ByteBuffer buf : outs.readyChunks()) {
            if (!trySendData(streamId, fin, buf, state)) {
                outbox.push(new FrameRecord(streamId, fin, buf));
            }
        }
    }

    private boolean trySendData(long streamId, boolean fin, ByteBuffer data, StreamState state) throws QuicStreamException {
        int dataSize = data.remaining();
        if (totalInFlightBytes + dataSize > currentMaxData) {
            logger.debug("Connection {} blocked by MAX_DATA: in-flight={}, data={}, limit={}",
                        connection.getConnectionId(), totalInFlightBytes, dataSize, currentMaxData);
            // Send DATA_BLOCKED frame to inform peer
            sendDataBlockedFrame(currentMaxData);
            return false;
        }

        // Check stream-level flow control (in-flight bytes vs MAX_STREAM_DATA)
        if (!state.canSendBytes(dataSize)) {
            logger.debug("Stream {} blocked by MAX_STREAM_DATA: in-flight={}, data={}, limit={}",
                    streamId, state.getInFlightBytes(), dataSize, state.getMaxStreamData());
            sendStreamDataBlockedFrame(streamId, state.getMaxStreamData());
            return false;
        }

        try {
            connection.enqueueApplicationData(data);

            // Update in-flight counters
            state.addSentBytes(dataSize); // Also updates stream in-flight
            totalInFlightBytes += dataSize;

            logger.debug("Sent {} bytes on stream {}: conn in-flight={}/{}, stream in-flight={}/{}",
                    dataSize, streamId, totalInFlightBytes, currentMaxData,
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
        if (connection.getState() != QuicConnection.State.ESTABLISHED) {
            throw new QuicStreamException("Connection is in wrong state " + connection.getState());
        }

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

        long bufferedBytesBefore = buffer.getBufferedBytes();
        StreamBuffer.StreamData data = buffer.readAvailableData();
        if (data != null) {
            long bufferedBytesAfter = buffer.getBufferedBytes();
            long freedBytes = bufferedBytesBefore - bufferedBytesAfter;

            // Update totalBufferedBytes when data is freed from buffer
            totalBufferedBytes -= freedBytes;

            QuicStreamResponseImpl response = new QuicStreamResponseImpl();
            handler.onStreamDataReceived(streamId, response, data.getData(), data.isLast(), errorCode);

            // Update MAX_DATA when data is freed from buffer
            updateMaxDataIfNeeded();
        }
    }

    private void sendMaxStreamDataFrame(long streamId, long maximumData) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeMaxStreamDataFrame(streamId, maximumData);
        try {
            connection.enqueueApplicationData(frame);
            StreamState state = streams.get(streamId);
            if (state != null) {
                state.setRemoteMaxStreamData(maximumData);
            }
        } catch (Exception e) {
            logger.error("Failed to send MAX_STREAM_DATA frame", e);
        }
    }

    private void sendMaxDataFrame(long maximumData) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeMaxDataFrame(maximumData);
        try {
            connection.enqueueApplicationData(frame);
            currentMaxData = maximumData;
            logger.debug("Sent MAX_DATA frame: maxData={}", maximumData);
        } catch (Exception e) {
            logger.error("Failed to send MAX_DATA frame", e);
        }
    }

    /**
     * Updates MAX_DATA when buffer space is freed.
     * MAX_DATA = hardMaxDataCapacity - totalBufferedBytes + totalReceivedBytes
     */
    private void updateMaxDataIfNeeded() {
        // New MAX_DATA = hardCapacity - bufferedBytes + totalReceived
        long newMaxData = maxDataCap - totalBufferedBytes + totalReceivedBytes;

        // Send MAX_DATA if the increase is significant
        if (currentMaxData - totalReceivedBytes > (maxDataCap - totalBufferedBytes)/2 ) {
            sendMaxDataFrame(newMaxData);
        }
    }

    private void sendResetStreamFrame(long streamId, long errorCode, long finalSize) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeResetStreamFrame(streamId, errorCode, finalSize);
        try {
            connection.enqueueApplicationData(frame);
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
            connection.enqueueApplicationData(frame);
        } catch (Exception e) {
            logger.error("Failed to send STOP_SENDING frame", e);
        }
    }

    private void sendStreamDataBlockedFrame(long streamId, long limit) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeStreamDataBlockedFrame(streamId, limit);
        try {
            connection.enqueueApplicationData(frame);
        } catch (Exception e) {
            logger.error("Failed to send STREAM_DATA_BLOCKED frame", e);
        }
    }

    public long getCurrentMaxData() {
        return currentMaxData;
    }

    public long getConnectionId() {
        return connection.getConnectionId();
    }

    /**
     * Sends DATA_BLOCKED frame to inform peer we're blocked at connection level.
     */
    private void sendDataBlockedFrame(long limit) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeDataBlockedFrame(limit);
        try {
            connection.enqueueApplicationData(frame);
            logger.debug("Sent DATA_BLOCKED frame: limit={}", limit);
        } catch (Exception e) {
            logger.error("Failed to send DATA_BLOCKED frame", e);
        }
    }

    /**
     * Implementation of QuicStreamResponse for this manager.
     */
    private class QuicStreamResponseImpl implements QuicStreamResponse {
        @Override
        public void closeConnection(long errorCode, String reason) throws QuicStreamException {
            connection.closeConnection(errorCode, reason);
        }

        @Override
        public long openStream(StreamType streamType) throws QuicStreamException {
            return StreamManager.this.openStream(streamType);
        }

        @Override
        public void closeStream(long streamId, long errorCode) throws QuicStreamException {
            StreamManager.this.closeStream(streamId, errorCode);
        }

        @Override
        public void sendData(long streamId, Consumer<DataOutputStream> writer, boolean fin) throws QuicStreamException {
            StreamManager.this.sendData(streamId, writer, fin);
        }
    }
}
