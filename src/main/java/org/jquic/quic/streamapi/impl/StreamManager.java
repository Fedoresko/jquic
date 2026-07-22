package org.jquic.quic.streamapi.impl;

import org.jquic.quic.PacketNumberSpace;
import org.jquic.quic.QuicConnection;
import org.jquic.quic.QuicTransportError;
import org.jquic.quic.QuicVarint;
import org.jquic.quic.buffers.ChunkedOutputStreamWithAmendments;
import org.jquic.quic.buffers.ChunkedOutputStreamWithAmendmentsImpl;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.streamapi.*;
import org.jquic.quic.streamapi.frames.*;
import org.jctools.queues.MessagePassingQueue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;

import static org.jquic.quic.QuicCrypto.GCM_TAG_LENGTH;
import static org.jquic.quic.streamapi.impl.StreamFrameProcessor.FRAME_TYPE_RESET_STREAM;

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
    public static final int DATAGRAM_FRAMES = -1;
    private final QuicStreamResponseImpl connectionControl = new QuicStreamResponseImpl();

    public record FrameRecord(long streamId, boolean fin, PoolBuffer data) {
    }

    private final QuicConnection connection;
    private final QuicApplicationProtocolConnectionHandler handler;
    private final ApplicationWorker streamWorker;
    private final CongestionControl congestionControl;
    private final FlightControl flightControl;
    private final QuicConnectionControl responseHandler = new QuicStreamResponseImpl();

    // Stream management
    private final Map<Long, StreamBuffer> streamBuffers = new HashMap<>();
    private final Map<Long, ChunkedOutputStreamWithAmendments> streamOutputs = new HashMap<>();
    private final MessagePassingQueue<OutboxRecord> outputQueue;

    private int outboxBytesBuffered = 0;
    // Stream counters - server always uses odd stream IDs
    private long nextServerBidiStreamId = 1;
    private long nextServerUniStreamId = 3;

    public StreamManager(QuicConnection connection,
                         QuicApplicationProtocolConnectionHandler handler,
                         QuicApplicationProtocol protocol,
                         ApplicationWorker streamWorker, MessagePassingQueue<OutboxRecord> outputQueue) {
        this.connection = connection;
        this.handler = handler;
        this.streamWorker = streamWorker;
        this.congestionControl = protocol.getCongestionControl();

        handler.setOutgoingDatagramStream(createOutputStream(DATAGRAM_FRAMES));

        flightControl = new FlightControl(connection.connectionMetadata.serverInitialStreamLimits,
                connection.connectionMetadata.clientMetadata.initialStreamLimits,this);
        this.outputQueue = outputQueue;
    }

    // Called from Selector thread
    @Override
    public void onProtocolFrame(ProtocolFrame frame) {
        streamWorker.enqueueFrame(this, frame);
    }

    //Called from Selector thread
    @Override
    public void onPacketAcknowledged(long packetNumber, PacketNumberSpace.SentPacket packet) {
        ByteBuffer payload = packet.getUnencryptedPayload().buf().duplicate();
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
    public long openStream(QuicConnectionControl.StreamType streamType) throws QuicStreamException {
        if (connection.getState() != QuicConnection.State.ESTABLISHED) {
            throw new QuicStreamException("Connection is in wrong state " + connection.getState());
        }

        long streamId;
        if (streamType == QuicConnectionControl.StreamType.Bidirectional) {
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

    public static QuicConnectionControl.StreamType getStreamType(Long id) {
        return (id & 0x02) == 0 ?
                QuicConnectionControl.StreamType.Bidirectional :
                QuicConnectionControl.StreamType.Unidirectional;
    }

    class FrameProcessor {

        /**
         * Called from Worker thread
         * Processes a frame. Called by worker thread only.
         */
        public void processFrame(ProtocolFrame frame, StreamManager streamManager) throws IOException {
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
            } else if (frame instanceof DatagramFrame) {
                handleFrame((DatagramFrame)frame);
            }
        }

        private void handleFrame(DatagramFrame frame) {
            //Copy buffer data into a new java byte array and release the native mem buffer.
            ByteBuffer buffer = ByteBuffer.allocate(frame.datagram.buf().remaining());
            buffer.put(frame.datagram.buf());
            handler.onDatagramReceived(buffer.array(), connectionControl);
            frame.datagram.release();
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
                ChunkedOutputStreamWithAmendmentsImpl outputStream = createOutputStream(streamId);
                streamOutputs.put(streamId, outputStream);
                handler.onNewClientStreamAllocated(streamId, responseHandler, outputStream, getStreamType(streamId));
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

            // Add data to the reassembly buffer - StreamBuffer enforces maxStreamData limit
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
                    StreamBuffer removed = streamBuffers.remove(streamId);
                    if (removed != null) {
                        removed.free();
                    }
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

    private @NonNull ChunkedOutputStreamWithAmendmentsImpl createOutputStream(long streamId) {
        final StreamBuffer streamBuffer = streamBuffers.get(streamId);
        ChunkedOutputStreamWithAmendmentsImpl out = new ChunkedOutputStreamWithAmendmentsImpl(connection.getBufferPool(),
                (int) connection.connectionMetadata.clientMetadata.maxUdpPayloadSize - GCM_TAG_LENGTH,
                GCM_TAG_LENGTH,
                (buf, off, fin) -> {
                    int dataSize = buf.remaining();
                    long offset = streamBuffer.allocateSendOffset(dataSize);
                    ByteBuffer encodedFrame = (streamId == DATAGRAM_FRAMES) ?
                            StreamFrameProcessor.encodeDatagramFrame(buf.duplicate(), true)
                            : StreamFrameProcessor.encodeStreamFrame(
                            streamId, offset, buf.duplicate(), fin);

                    if (logger.isDebugEnabled()) {
                        byte[] tt = new byte[encodedFrame.remaining()];
                        encodedFrame.duplicate().get(tt);
                        logger.debug("Sending STREAM resp {}", HexFormat.of().formatHex(tt));
                    }
                    int chunkEnd = encodedFrame.limit();
                    buf.limit(buf.capacity());
                    buf.position(chunkEnd + STREAM_FRAME_HEADER_MAX_LEN);
                    if (fin) {
                        streamOutputs.remove(streamId);
                    }
                    return encodedFrame;
                }
        );
        out.setChunkConsumer(buf -> appendOutgoingData(streamId, buf));
        return out;
    }

    /**
     * Appends ready to send Buffer from a stream to outputQueue.
     * Called from the Worker thread.
     */
    public void appendOutgoingData(long streamId, PoolBuffer data) throws IOException {
        if (connection.getState() != QuicConnection.State.ESTABLISHED) {
            logger.error("Connection is in wrong state " + connection.getState());
            return;
        }

        if (streamId != DATAGRAM_FRAMES && !flightControl.isStreamOpenForSend(streamId)) {
            throw new IOException("Stream " + streamId + " cannot send data in stream.");
        }

        int dataSize = data.buf().remaining();

        if (streamId != DATAGRAM_FRAMES && !flightControl.canSend(streamId, dataSize)) {
            logger.warn("Cannot push more data for stream {}", streamId);
            throw new IOException("Cannot push more data for stream " + streamId);
        }

        long delayNs = getCongestionDelayNanos(streamId, dataSize, dataSize);

        logger.warn("Connection {} stream {} has been data {}b to be sent in {} ns", connection.getConnectionId(), streamId, dataSize, delayNs);

        outputQueue.relaxedOffer(new OutboxRecord(getConnectionId(), System.nanoTime() + delayNs, data));

        outboxBytesBuffered += dataSize;
    }

    @Override
    public void onDataSend(int dataSize) {
        outboxBytesBuffered -= dataSize;
    }

    @Override
    public void onConnectionClose() {
        handler.onConnectionClose();
        for (long stramId : new HashSet<>(streamBuffers.keySet()))
            streamBuffers.remove(stramId).free();
        try {
            for (long stramId : new HashSet<>(streamOutputs.keySet()))
                streamOutputs.remove(stramId).close();
        } catch (IOException e) {
            logger.warn("Error closing output stream", e);
        }
    }

    private long getCongestionDelayNanos(long streamId, int dataSize, int bufferedBytes) {
        PacketNumberSpace.WindowedStats windowedStats = connection.getApplicationSpace().getWindowedStats();
        StreamBuffer streamBuffer = streamBuffers.get(streamId);
        return congestionControl.canSend(
            System.currentTimeMillis(),
            dataSize,
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
            streamBuffer != null ? flightControl.maxStreamDataCap - streamBuffer.getBufferedBytes() : flightControl.maxStreamDataCap ,
            bufferedBytes,
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
        PoolBuffer frame = StreamFrameProcessor.encodeMaxStreamsFrame(connection.getBufferPool(), maximumStreams, bidirectional);
        try {
            long delayNs = getCongestionDelayNanos(0, frame.buf().remaining(), outboxBytesBuffered);
            outputQueue.offer(new OutboxRecord(getConnectionId(), System.nanoTime() + delayNs, frame));
            logger.debug("Sent MAX_STREAMS frame: maxStreams={}, bidirectional={}", maximumStreams, bidirectional);
        } catch (Exception e) {
            logger.error("Failed to send MAX_STREAMS frame", e);
        }
    }

    void sendMaxStreamDataFrame(long streamId, long maximumData) {
        PoolBuffer frame = StreamFrameProcessor.encodeMaxStreamDataFrame(connection.getBufferPool(), streamId, maximumData);
        try {
            long delayNs = getCongestionDelayNanos(streamId, frame.buf().remaining(), outboxBytesBuffered);
            outputQueue.offer(new OutboxRecord(getConnectionId(), System.nanoTime() + delayNs, frame));
        } catch (Exception e) {
            logger.error("Failed to send MAX_STREAM_DATA frame", e);
        }
    }

    void sendMaxDataFrame(long maximumData, long streamId) {
        PoolBuffer frame = StreamFrameProcessor.encodeMaxDataFrame(connection.getBufferPool(), maximumData);
        try {
            long delayNs = getCongestionDelayNanos(streamId, frame.buf().remaining(), outboxBytesBuffered);
            outputQueue.offer(new OutboxRecord(getConnectionId(), System.nanoTime() + delayNs, frame));
            logger.debug("Sent MAX_DATA frame: maxData={}", maximumData);
        } catch (Exception e) {
            logger.error("Failed to send MAX_DATA frame", e);
        }
    }

    void sendResetStreamFrame(long streamId, long errorCode, long finalSize) {
        PoolBuffer frame = StreamFrameProcessor.encodeResetStreamFrame(connection.getBufferPool(), streamId, errorCode, finalSize);
        try {
            long delayNs = getCongestionDelayNanos(streamId, frame.buf().remaining(), outboxBytesBuffered);
            outputQueue.offer(new OutboxRecord(getConnectionId(), System.nanoTime() + delayNs, frame));
        } catch (Exception e) {
            logger.error("Failed to send RESET_STREAM frame", e);
        }
    }

    void sendStopSendingFrame(long streamId, long errorCode) {
        PoolBuffer frame = StreamFrameProcessor.encodeStopSendingFrame(connection.getBufferPool(), streamId, errorCode);
        try {
            long delayNs = getCongestionDelayNanos(streamId, frame.buf().remaining(), outboxBytesBuffered);
            outputQueue.offer(new OutboxRecord(getConnectionId(), System.nanoTime() + delayNs, frame));
        } catch (Exception e) {
            logger.error("Failed to send STOP_SENDING frame", e);
        }
    }

    void sendStreamDataBlockedFrame(long streamId, long limit) {
        PoolBuffer frame = StreamFrameProcessor.encodeStreamDataBlockedFrame(connection.getBufferPool(), streamId, limit);
        try {
            long delayNs = getCongestionDelayNanos(streamId, frame.buf().remaining(), outboxBytesBuffered);
            outputQueue.offer(new OutboxRecord(getConnectionId(), System.nanoTime() + delayNs, frame));
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
    void sendDataBlockedFrame(long limit, long streamId) {
        PoolBuffer frame = StreamFrameProcessor.encodeDataBlockedFrame(connection.getBufferPool(), limit);
        try {
            long delayNs = getCongestionDelayNanos(streamId, frame.buf().remaining(), outboxBytesBuffered);
            outputQueue.offer(new OutboxRecord(getConnectionId(), System.nanoTime() + delayNs, frame));
            logger.debug("Sent DATA_BLOCKED frame: limit={}", limit);
        } catch (Exception e) {
            logger.error("Failed to send DATA_BLOCKED frame", e);
        }
    }

    /**
     * Implementation of QuicStreamResponse for this manager.
     */
    private class QuicStreamResponseImpl implements QuicConnectionControl {
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
    }
}
