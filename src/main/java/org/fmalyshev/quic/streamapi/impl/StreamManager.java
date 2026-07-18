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
import java.util.concurrent.locks.LockSupport;
import java.util.function.Consumer;

import static org.fmalyshev.quic.streamapi.impl.StreamFrameProcessor.FRAME_TYPE_RESET_STREAM;

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

    record FrameRecord(long streamId, boolean fin, ByteBuffer data) {
    }

    private final QuicConnection connection;
    private final QuicApplicationProtocolConnectionHandler handler;
    private final StreamWorker streamWorker;
    private final CongestionControl congestionControl;
    private final FlightControl flightControl;
    private final QuicStreamResponse responseHandler = new QuicStreamResponseImpl();

    // Stream management
    private final Map<Long, StreamBuffer> streamBuffers = new HashMap<>();
    private final Deque<FrameRecord> outbox = new ArrayDeque<>();
    private long outboxBytesBuffered = 0;
    // Stream counters - server always uses odd stream IDs
    private long nextServerBidiStreamId = 1;
    private long nextServerUniStreamId = 3;

    public StreamManager(QuicConnection connection,
                         QuicApplicationProtocolConnectionHandler handler,
                         QuicApplicationProtocol protocol,
                         StreamWorker streamWorker) {
        this.connection = connection;
        this.handler = handler;
        this.streamWorker = streamWorker;
        this.congestionControl = protocol.getCongestionControl();

        flightControl = new FlightControl(connection.connectionMetadata.serverInitialStreamLimits,
                connection.connectionMetadata.clientMetadata.initialStreamLimits,this);
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
        if (payload.hasRemaining()) {
            byte ackedFrameType = payload.get();
            // Check if this is a STREAM frame (0x08-0x0f)
            if (ackedFrameType >= 0x08 && ackedFrameType <= 0x0f) {
                boolean hasLength = (ackedFrameType & 0x02) != 0;
                long streamId = QuicVarint.read(payload);
                long length = (hasLength) ? QuicVarint.read(payload) : payload.remaining();

                streamWorker.enqueueAck(this, streamId, length);
                payload.position(Math.min(payload.limit(), payload.position() + (int) length));
            }
            if (ackedFrameType == FRAME_TYPE_RESET_STREAM) {
                long streamId = QuicVarint.read(payload);
                streamWorker.enqueueFrame(this, new StreamResetFrameAck(streamId));
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

        flightControl.openOutgoingStream(streamId, streamType);
        // Create stream state
        StreamBuffer buffer = new StreamBuffer(streamId, flightControl.maxStreamDataCap);
        streamBuffers.put(streamId, buffer);

        // Note: Handler callback will be called when worker thread processes first frame
        // or when explicitly allocated by application

        logger.debug("Opened new stream {} (type: {}, server: true)", streamId, streamType);
        return streamId;
    }

    FrameProcessor frameProcessor = new FrameProcessor();

    void sendConnectionClose(QuicTransportError quicTransportError, String reason) {
        connection.closeConnection(quicTransportError, reason);
    }

    public static QuicStreamResponse.StreamType getStreamType(Long id) {
        return (id & 0x02) == 0 ?
                QuicStreamResponse.StreamType.Bidirectional :
                QuicStreamResponse.StreamType.Unidirectional;
    }

    class FrameProcessor {

        /**
         * Called from Worker thread
         * Processes a frame. Called by worker thread only.
         */
        public boolean processFrame(StreamFrame frame, StreamManager streamManager) throws IOException {
            FrameRecord record;
            while ((record = streamManager.outbox.poll()) != null) {
                int size = record.data.remaining();
                if (!streamManager.trySendData(record.streamId, record.fin, record.data, false)) {
                    logger.info("Pending answers still cannot be send, stop processing new frames CID {}", streamManager.connection.getConnectionId());
                    streamManager.outbox.push(record);
                    return false;
                }
                outboxBytesBuffered -= size;
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
            } else if (frame instanceof MaxDataFrameData) {
                handleFrame((MaxDataFrameData) frame);
            } else if (frame instanceof MaxStreamsFrameData) {
                handleFrame((MaxStreamsFrameData) frame);
            } else if (frame instanceof StreamDataBlockedFrameData) {
                handleFrame((StreamDataBlockedFrameData) frame);
            } else if (frame instanceof StreamsBlockedFrameData) {
                handleFrame((StreamsBlockedFrameData) frame);
            } else  if (frame instanceof StreamResetFrameAck) {
                onStreamResetAck(((StreamResetFrameAck) frame).streamId);
            }
            return true;
        }

        /**
         * Called from Worker thread.
         * Process acknowledged stream bytes.
         */
        public void processAck(long streamId, Long ackTotalLength) {
            // Update stream flow control
            flightControl.bytesAcked(streamId, ackTotalLength);
        }

        private void handleFrame(StreamFrameData frame) throws IOException {
            long streamId = frame.streamId;
            long offset = frame.offset;
            PoolBuffer data = frame.data;
            boolean hasFin = frame.fin;

            // Ensure stream and buffer exist
            StreamState.State state = flightControl.incomingStream(streamId);

            if (state == null || !state.canReceive()) {
                logger.warn("Received STREAM frame on stream {} in state {}", streamId, state);
                return;
            }

            if (!streamBuffers.containsKey(streamId)) {
                streamBuffers.put(streamId, new StreamBuffer(streamId, flightControl.maxStreamDataCap));
                QuicStreamResponseImpl response = new QuicStreamResponseImpl();
                handler.onNewStreamAllocated(streamId, response, false, getStreamType(streamId));
            }

            StreamBuffer streamBuffer = streamBuffers.get(streamId);
            if (streamBuffer == null) {
                logger.warn("Stream buffer not found for stream {}", streamId);
                return;
            }
            // Update state
            int dataSize = data.buf().remaining();

            if (flightControl.isReceiveCapReached(streamId, offset, dataSize)) return;
            flightControl.addReceivedBytes(streamId, offset, dataSize, streamBuffer.getBufferedBytes());

            // Add data to reassembly buffer - StreamBuffer enforces maxStreamData limit
            if (streamBuffer.addIncomingData(offset, data, hasFin)) {
                // Deliver contiguous data to handler
                deliverStreamData(streamId, null);
            } else {
                logger.warn("Connection {} stream {} has reached MAX_STREAM_DATA", getConnectionId(), streamId);
                connection.closeConnection(QuicTransportError.FLOW_CONTROL_ERROR, "MAX_STREAM_DATA limit reached");
            }
        }

        private void handleFrame(ResetStreamFrameData frame) throws IOException {
            long streamId = frame.streamId;
            long errorCode = frame.errorCode;
            logger.info("Stream {} reset by peer with error code {}", streamId, errorCode);

            flightControl.onStreamReset(streamId, errorCode, frame.finalSize);

            // Deliver any buffered data with error code
            frameProcessor.deliverStreamData(streamId, errorCode);
            streamBuffers.remove(streamId).free();
        }

        private void handleFrame(StopSendingFrameData frame) {
            flightControl.onStreamStopSending(frame.streamId, frame.errorCode);
        }

        private void handleFrame(MaxStreamDataFrameData frame) {
            flightControl.onStreamMaxData(frame.streamId, frame.maximumData);
        }

        private void handleFrame(MaxDataFrameData frame) {
            flightControl.onMaxData(frame.maximumData);
        }

        private void handleFrame(MaxStreamsFrameData frame) {
            flightControl.onMaxStreams(frame.bidirectional, frame.maximumStreams);
        }

        private void handleFrame(StreamDataBlockedFrameData frame) {
            flightControl.onStreamDataBlocked(frame.streamId, frame.limit, streamBuffers.get(frame.streamId).getBufferedBytes());
        }

        private void handleFrame(StreamsBlockedFrameData frame) {
            long limit = frame.limit;
            logger.debug("Peer is blocked on {} streams at limit {}",
                    frame.bidirectional ? "bidi" : "uni", limit);
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
                flightControl.byfferedBytesFreed(streamId, freedBytes);

                handler.onStreamDataReceived(streamId, responseHandler, data.getData(), data.isLast(), errorCode);

                if (data.isLast()) {
                    flightControl.onStreamFin(streamId, false);
                    streamBuffers.remove(streamId).free();
                }
            } else if (errorCode != null) {
                handler.onStreamDataReceived(streamId, responseHandler, new byte[0], true, errorCode);
            }
        }

        private void onStreamResetAck(long streamId) {
            flightControl.onStreamResetAck(streamId);
            StreamBuffer buffer = streamBuffers.remove(streamId);
            if (buffer != null) {
                buffer.free();
            } else {
                logger.warn("onStreamResetAck: stream {} is already gone", streamId);
            }
        }
    }


    /**
     * Sends data on a stream immediately.
     * Called from worker thread (via QuicStreamResponse).
     */
    public void sendData(long streamId, Consumer<DataOutputStream> writer, boolean fin, boolean isBlocking) throws QuicStreamException {
        if (connection.getState() != QuicConnection.State.ESTABLISHED) {
            throw new QuicStreamException("Connection is in wrong state " + connection.getState());
        }

        if (!flightControl.isStreamOpenForSend(streamId)) {
            throw new QuicStreamException("Stream " + streamId + " cannot send data in stream.");
        }

        ByteBuffer data = ByteBuffer.allocateDirect(2048);
        data.position(STREAM_FRAME_HEADER_MAX_LEN);

        ChunkedOutputStreamWithAmendmentsImpl outs = new ChunkedOutputStreamWithAmendmentsImpl(data,
                (int) connection.connectionMetadata.clientMetadata.maxUdpPayloadSize - 16,
                (buf, off) -> {
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

        outs.setChunkConsumer(packet -> {
                if (!trySendData(streamId, fin, packet, isBlocking)) {
                    if ((outboxBytesBuffered + packet.remaining()) > flightControl.maxStreamDataCap) {
                        throw new IllegalStateException("Buffer overflow.");
                    }
                    outboxBytesBuffered += packet.remaining();
                    outbox.push(new FrameRecord(streamId, fin, packet));
                }
            }
        );

        writer.accept(outs);

        try {
            outs.close();
        } catch (IOException e) {
            throw new QuicStreamException("Cant write stream data", e);
        }
    }

    private boolean trySendData(long streamId, boolean fin, ByteBuffer data, boolean isBlocking) {
        int dataSize = data.remaining();
        if (!flightControl.canSend(streamId, dataSize)) {
            logger.warn("Cannot push more data for stream {}", streamId);
            return false;
        }

        long delayNs = getCongestionDelayNanos(streamId, data);
        if (delayNs > 0) {
            if (isBlocking) {
                LockSupport.parkNanos(delayNs);
            } else  {
                logger.warn("Stream {} was delayed by {} ns", streamId,  delayNs);
                return false;
            }
        }

        connection.enqueueApplicationData(data);

        // Update in-flight counters
        flightControl.addSentBytes(streamId, dataSize);
        logger.debug("Sent {} bytes on stream {}",
                dataSize, streamId);

        // Update state
        if (fin) {
            flightControl.onStreamFin(streamId, true);
        }
        return true;
    }

    private long getCongestionDelayNanos(long streamId, ByteBuffer data) {
        PacketNumberSpace.WindowedStats windowedStats = connection.getApplicationSpace().getWindowedStats();
        return congestionControl.canSend(
            System.currentTimeMillis(),
            data.remaining(),
            connection.getConnectionId(),
                streamId,
            connection.getApplicationSpace().getSmoothedRtt(),
            connection.getApplicationSpace().getLatestRtt(),
            connection.getApplicationSpace().getMinRtt(),
            windowedStats.bytesAckedInLastRtt(),
            windowedStats.bytesLostInLastRtt(),
            windowedStats.bytesAcked(),
            windowedStats.bytesLost(),
            windowedStats.packetsAcked(),
            connection.getApplicationSpace().getLossTime(),
            flightControl.getTotalInFlightBytes(),
            flightControl.maxStreamDataCap - streamBuffers.get(streamId).getBufferedBytes(),
                outboxBytesBuffered,
            connection.getApplicationSpace().getServerCeCounter(),
            windowedStats.intervalCePackets()
        );
    }

    /**
     * Closes a stream by sending STOP_SENDING.
     */
    public void closeStream(long streamId, long errorCode) throws QuicStreamException {
        if (connection.getState() != QuicConnection.State.ESTABLISHED) {
            throw new QuicStreamException("Connection is in wrong state " + connection.getState());
        }
        if (!streamBuffers.containsKey(streamId)) {
            throw new QuicStreamException("Stream " + streamId + " does not exist");
        }
        flightControl.closeStream(streamId, errorCode);
    }

    void sendMaxStreamsFrame(long maximumStreams, boolean bidirectional) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeMaxStreamsFrame(maximumStreams, bidirectional);
        try {
            connection.enqueueApplicationData(frame);
            logger.debug("Sent MAX_STREAMS frame: maxStreams={}, bidirectional={}", maximumStreams, bidirectional);
        } catch (Exception e) {
            logger.error("Failed to send MAX_STREAMS frame", e);
        }
    }

    void sendMaxStreamDataFrame(long streamId, long maximumData) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeMaxStreamDataFrame(streamId, maximumData);
        try {
            connection.enqueueApplicationData(frame);
        } catch (Exception e) {
            logger.error("Failed to send MAX_STREAM_DATA frame", e);
        }
    }

    void sendMaxDataFrame(long maximumData) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeMaxDataFrame(maximumData);
        try {
            connection.enqueueApplicationData(frame);
            logger.debug("Sent MAX_DATA frame: maxData={}", maximumData);
        } catch (Exception e) {
            logger.error("Failed to send MAX_DATA frame", e);
        }
    }

    void sendResetStreamFrame(long streamId, long errorCode, long finalSize) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeResetStreamFrame(streamId, errorCode, finalSize);
        try {
            connection.enqueueApplicationData(frame);
        } catch (Exception e) {
            logger.error("Failed to send RESET_STREAM frame", e);
        }
    }

    void sendStopSendingFrame(long streamId, long errorCode) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeStopSendingFrame(streamId, errorCode);
        try {
            connection.enqueueApplicationData(frame);
        } catch (Exception e) {
            logger.error("Failed to send STOP_SENDING frame", e);
        }
    }

    void sendStreamDataBlockedFrame(long streamId, long limit) {
        java.nio.ByteBuffer frame = StreamFrameProcessor.encodeStreamDataBlockedFrame(streamId, limit);
        try {
            connection.enqueueApplicationData(frame);
        } catch (Exception e) {
            logger.error("Failed to send STREAM_DATA_BLOCKED frame", e);
        }
    }

    public long getConnectionId() {
        return connection.getConnectionId();
    }

    /**
     * Sends DATA_BLOCKED frame to inform peer we're blocked at connection level.
     */
    void sendDataBlockedFrame(long limit) {
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
        public void closeConnection(long errorCode, String reason) {
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
            StreamManager.this.sendData(streamId, writer, fin, true);
        }

        @Override
        public void trySendData(long streamId, Consumer<DataOutputStream> writer, boolean fin) throws QuicStreamException {
            StreamManager.this.sendData(streamId, writer, fin, false);
        }
    }
}
