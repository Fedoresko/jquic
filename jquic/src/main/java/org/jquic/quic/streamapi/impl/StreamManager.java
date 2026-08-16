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

import org.jctools.queues.MessagePassingQueue;
import org.jquic.quic.*;
import org.jquic.quic.buffers.ChunkedOutputStreamWithAmendments;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.streamapi.*;
import org.jquic.quic.streamapi.frames.*;
import org.jquic.quic.struct.TriStateQueue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.LockSupport;

import static org.jquic.quic.crypto.QuicCrypto.GCM_TAG_LENGTH;
import static org.jquic.quic.streamapi.impl.StreamFrameWriter.FRAME_TYPE_RESET_STREAM;

/**
 * Manages all streams for a single QUIC connection.
 * Handles stream lifecycle, frame processing, and flow control.
 * Stream manager is bound to a particular Worker thread in which all user requests are processed.
 * Thread-safety: ALL methods except {#onStreamFrame} and {#onPacketAcknowledged} are called from
 * worker thread only - no synchronization needed.
 */
public class StreamManager implements ConnectionStreamManager {
    private static final Logger logger = LoggerFactory.getLogger(StreamManager.class);
    public static final int STREAM_BUFFER_CAPACITY = 50_000;
    public static final int DATAGRAM_FRAMES = -1;
    public static final int SERVICE_DATA = -2;
    private final QuicStreamResponseImpl datagramConnectionControl = new QuicStreamResponseImpl(null);

    private final QuicConnection connection;
    private final QuicApplicationProtocolConnectionHandler handler;
    private final ApplicationWorker streamWorker;
    private final FlightControl flightControl;

    // Stream management
    private final Map<Long, StreamBuffer> streamBuffers = new HashMap<>();
    private final Map<Long, ChunkedOutputStreamWithAmendments> streamOutputs = new HashMap<>();
    private final MessagePassingQueue<TriStateQueue<ApplicationData>> wakeQueue;

    private final TriStateQueue<ApplicationData> serviceQueue = new TriStateQueue<>(ApplicationData.EMPTY, ApplicationData.PROCESSED);

    // Stream counters - server always uses odd stream IDs
    private long nextServerBidiStreamId = 1;
    private long nextServerUniStreamId = 3;

    public StreamManager(QuicConnection connection,
                         QuicApplicationProtocol protocol,
                         ApplicationWorker streamWorker, MessagePassingQueue<TriStateQueue<ApplicationData>> wakeQueue) {
        this.connection = connection;
        this.streamWorker = streamWorker;
        flightControl = new FlightControl(connection.connectionMetadata.serverInitialLimits,
                connection.connectionMetadata.clientMetadata.initialStreamLimits, this);
        this.wakeQueue = wakeQueue;

        handler = protocol.getConnectionHandler().apply(connection.getConnectionId());
        handler.setOutgoingDatagramStream(createOutputStream(new StreamState(DATAGRAM_FRAMES, QuicConnectionControl.StreamType.Bidirectional, Long.MAX_VALUE, Long.MAX_VALUE)));
        handler.onConnectionEstablished(new QuicStreamResponseImpl(null));
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
            SreamFrameDetails frameDetails = parseStreamFrameDetails(payload);
            // Check if this is a STREAM frame (0x08-0x0f)
            if (frameDetails.frameType >= 0x08 && frameDetails.frameType <= 0x0f) {
                payload.position(Math.min(payload.limit(), payload.position() + (int) frameDetails.length()));
                streamWorker.enqueueAck(this, frameDetails.streamId(), frameDetails.offset(), frameDetails.length());
            }
            if (frameDetails.frameType == FRAME_TYPE_RESET_STREAM) {
                streamWorker.enqueueFrame(this, new StreamResetFrameAck(frameDetails.streamId));
            }
        }
    }

    private static @NonNull SreamFrameDetails parseStreamFrameDetails(ByteBuffer payload) {
        byte frameType = payload.get();
        boolean hasLength = (frameType & 0x02) != 0;
        long streamId = QuicVarint.read(payload);
        boolean hasOffset = (frameType & 0x04) != 0;
        long offset = 0;
        if (hasOffset) offset = QuicVarint.read(payload);
        long length = (hasLength) ? QuicVarint.read(payload) : payload.remaining();
        return new SreamFrameDetails(frameType, streamId, length, offset);
    }

    private record SreamFrameDetails(byte frameType, long streamId, long length, long offset) {
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

        StreamState state = flightControl.openOutgoingStream(streamId, streamType);
        // Create stream state
        StreamBuffer buffer = new StreamBuffer(streamId, flightControl.getMaxStreamDataCap());
        streamBuffers.put(streamId, buffer);

        ChunkedOutputStreamWithAmendments outputStream = createOutputStream(state);
        streamOutputs.put(streamId, outputStream);
        handler.onNewServerStreamAllocated(streamId, outputStream, streamType);

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
        public void processFrame(ProtocolFrame frame) throws IOException {
            // Route based on frame type and decode using StreamFrameProcessor
            switch (frame) {
                case StreamFrameData streamFrameData -> handleFrame(streamFrameData);
                case ResetStreamFrameData resetStreamFrameData -> handleFrame(resetStreamFrameData);
                case StopSendingFrameData stopSendingFrameData -> handleFrame(stopSendingFrameData);
                case MaxStreamDataFrameData maxStreamDataFrameData -> handleFrame(maxStreamDataFrameData);
                case MaxDataFrameData maxDataFrameData -> handleFrame(maxDataFrameData);
                case MaxStreamsFrameData maxStreamsFrameData -> handleFrame(maxStreamsFrameData);
                case StreamDataBlockedFrameData streamDataBlockedFrameData -> handleFrame(streamDataBlockedFrameData);
                case StreamsBlockedFrameData streamsBlockedFrameData -> handleFrame(streamsBlockedFrameData);
                case StreamResetFrameAck streamResetFrameAck -> onStreamResetAck(streamResetFrameAck.streamId);
                case DatagramFrame datagramFrame -> handleFrame(datagramFrame);
                default -> logger.warn("Unknown frame type {}", frame.getClass().getName());
            }
        }

        private void handleFrame(DatagramFrame frame) {
            //Copy buffer data into a new java byte array and release the native mem buffer.
            ByteBuffer buffer = ByteBuffer.allocate(frame.datagram.buf().remaining());
            buffer.put(frame.datagram.buf());
            handler.onDatagramReceived(buffer.array(), datagramConnectionControl);
            frame.datagram.release();
        }

        /**
         * Called from Worker thread.
         * Process acknowledged stream bytes.
         */
        public void processAck(long streamId, Long offset, Long length) {
            // Update stream flow control
            flightControl.bytesAcked(streamId, offset, length);
        }

        private void handleFrame(StreamFrameData frame) throws IOException {
            if (connection.getState() != QuicConnection.State.ESTABLISHED) {
                logger.warn("Connection is in wrong state " + connection.getState());
                frame.data.release();
                return;
            }

            long streamId = frame.streamId;
            int offset = (int)frame.offset;
            PoolBuffer data = frame.data;
            boolean hasFin = frame.fin;

            // Ensure stream and buffer exist
            StreamState state = flightControl.incomingStream(streamId);

            if (state == null || !state.getState().canReceive()) {
                logger.warn("Received STREAM frame on stream {} in state {}", streamId, state == null ? "REMOVED" : state.getState());
                data.release();
                return;
            }

            if (!streamBuffers.containsKey(streamId)) {
                streamBuffers.put(streamId, new StreamBuffer(streamId, flightControl.getMaxStreamDataCap()));
                QuicConnectionControl.StreamType streamType = getStreamType(streamId);
                ChunkedOutputStreamWithAmendments outputStream = null;
                if (streamType == QuicConnectionControl.StreamType.Bidirectional) {
                    outputStream = createOutputStream(state);
                    streamOutputs.put(streamId, outputStream);
                }
                handler.onNewClientStreamAllocated(streamId, new QuicStreamResponseImpl(state), outputStream, streamType);
            }

            StreamBuffer streamBuffer = streamBuffers.get(streamId);
            if (streamBuffer == null) {
                logger.warn("Stream buffer not found for stream {}", streamId);
                return;
            }
            // Update state
            int dataSize = data.buf().remaining();

            if (flightControl.isReceiveCapReached(state, offset, dataSize)) return;

            flightControl.addReceivedBytes(state, offset, dataSize);

            try {
                if (streamBuffer.addIncomingData(offset, data, hasFin)) {
                    deliverStreamData(state, null);
                }
            } catch (QuicException e) {
                logger.warn("Connection {} stream {} has encountered an error", getConnectionId(), streamId, e);
                connection.closeConnection(e.getError(), e.getMessage());
            }
        }

        private void handleFrame(ResetStreamFrameData frame) throws IOException {
            long streamId = frame.streamId;
            long errorCode = frame.errorCode;
            logger.info("Stream {} reset by peer with error code {}", streamId, errorCode);


            StreamState state = flightControl.onStreamReset(streamId, errorCode, frame.finalSize);

            // Deliver any buffered data with error code
            if (state != null) {
                frameProcessor.deliverStreamData(state, errorCode);
            }
            streamOutputs.remove(streamId).close();
            streamBuffers.remove(streamId).free();
        }

        private void handleFrame(StopSendingFrameData frame) {
            flightControl.onStreamStopSending(frame.streamId, frame.errorCode);
        }

        private void handleFrame(MaxStreamDataFrameData frame) {
            logger.warn("Processing MaxStreamDataFrameData {} max: {}", frame.streamId, frame.maximumData);
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
        private void deliverStreamData(StreamState state, @Nullable Long errorCode) throws IOException {
            long streamId = state.getStreamId();
            StreamBuffer buffer = streamBuffers.get(streamId);
            if (buffer == null) return;

            long bufferedBytesBefore = buffer.getBufferedBytes();
            StreamBuffer.StreamData data = buffer.readAvailableData();

            if (data != null) {
                long bufferedBytesAfter = buffer.getBufferedBytes();
                long freedBytes = bufferedBytesBefore - bufferedBytesAfter;
                // Update totalBufferedBytes when data is freed from buffer
                flightControl.bufferedBytesFreed(streamId, freedBytes);

                handler.onStreamDataReceived(streamId, new QuicStreamResponseImpl(state), data.getData(), data.isLast(), errorCode);

                if (data.isLast()) {
                    flightControl.onStreamFin(state, false);
                    StreamBuffer removed = streamBuffers.remove(streamId);
                    if (removed != null) {
                        removed.free();
                    }
                }
            } else if (errorCode != null) {
                handler.onStreamDataReceived(streamId, new QuicStreamResponseImpl(state) , new byte[0], true, errorCode);
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

    private @NonNull ChunkedOutputStreamWithAmendments createOutputStream(StreamState state) {
        long streamId = state.getStreamId();
        ChunkedOutputStreamWithAmendments out = ChunkedOutputStreamWithAmendments.createNonWrapping(connection.getBufferPool(),
                (int) connection.connectionMetadata.clientMetadata.maxUdpPayloadSize - GCM_TAG_LENGTH - QuicFrameBuilder.MAX_SHORT_HEADER_LENGTH,
                GCM_TAG_LENGTH + QuicFrameBuilder.MAX_SHORT_HEADER_LENGTH,
                (buf, offset, fin) -> (streamId == DATAGRAM_FRAMES) ?
                        StreamFrameWriter.encodeDatagramFrame(buf.duplicate(), true)
                        : StreamFrameWriter.encodeStreamFrame(
                        streamId, offset, buf.duplicate(), fin)
        );
        out.setChunkConsumer(buf -> appendOutgoingData(state, buf));
        return out;
    }

    /**
     * Appends ready to send Buffer from a stream to outputQueue.
     * Called from the Worker thread.
     */
    public void appendOutgoingData(StreamState state, PoolBuffer data) throws IOException {
        long streamId = state.getStreamId();
        if (connection.getState() != QuicConnection.State.ESTABLISHED) {
            logger.error("Connection is in wrong state " + connection.getState());
            data.release();
            throw new IOException("Connection is " + connection.getState());
        }

        if (streamId != DATAGRAM_FRAMES && !flightControl.isStreamOpenForSend(state)) {
            throw new IOException("Stream " + streamId + " cannot send data in stream.");
        }

        int dataSize = data.buf().remaining();

        while (streamId != DATAGRAM_FRAMES && !flightControl.canSend(state, dataSize)) {
            long smoothedRtt = connection.getApplicationSpace().getSmoothedRtt();
            LockSupport.parkNanos(smoothedRtt * 1_000_000L);
            if (connection.getState() != QuicConnection.State.ESTABLISHED) {
                data.release();
                throw new IOException("Connection is " + connection.getState());
            }
        }

        SreamFrameDetails details = parseStreamFrameDetails(data.buf().duplicate());

        try {
            trySendData(state.getSendQueue(), streamId, data);
        } catch (TimeoutException t) {
            throw new IOException("Timeout writing data into connection");
        }

        flightControl.updateMaxSentOffset(state, details.offset + details.length);

        logger.info("Stream #{} maxSreamData {} remoteMaxStreamData {}, maxSentOffset {}, bufferesBytes {}, maxOffset {}", streamId, state.getMaxStreamData(), state.getRemoteMaxStreamData(), state.getMaxSentOffset(), state.getBufferedBytes(), state.getMaxOffset());
        logger.info("Total CID#{} buffered {}, in-flight {}, totalMaxOffsetsSum {}", getConnectionId(), flightControl.getBytesBuffered(), flightControl.getTotalInFlightBytes(), flightControl.totalMaxOffsetsSum);
    }

    private void trySendData(TriStateQueue<ApplicationData> queue, long streamId, PoolBuffer data) throws TimeoutException {
        boolean needWake = queue.put(new ApplicationData(connection, flightControl, streamId, data), 10_000L,
                1_000_000_000L);
        if (needWake) {
            wakeQueue.relaxedOffer(queue);
        }
    }

    @Override
    public void onConnectionClose() {
        handler.onConnectionClose();
        for (long stramId : new HashSet<>(streamBuffers.keySet())) {
            StreamBuffer buffer = streamBuffers.remove(stramId);
            if (buffer.getBufferedBytes() > 0) {
                logger.warn("Stream Buffer #{} still has input data {}", stramId, buffer.getBufferedBytes());
                buffer.logIncomingFragments();
            }
            buffer.free();
        }
        for (long stramId : new HashSet<>(streamOutputs.keySet()))
            streamOutputs.remove(stramId);
    }

    /**
     * Closes a stream by sending STOP_SENDING.
     */
    public void closeStream(long streamId, StreamState state, long errorCode) throws QuicStreamException {
        if (state == null) return;

        if (connection.getState() != QuicConnection.State.ESTABLISHED) {
            logger.info("Connection is in wrong state " + connection.getState());
            return;
        }
        if (!streamBuffers.containsKey(streamId)) {
            throw new QuicStreamException("Stream " + streamId + " does not exist");
        }
        flightControl.closeStream(state,  errorCode);
    }

    void sendMaxStreamsFrame(long maximumStreams, boolean bidirectional) {
        PoolBuffer frame = StreamFrameWriter.encodeMaxStreamsFrame(connection.getBufferPool(), maximumStreams, bidirectional);
        try {
            trySendData(serviceQueue, SERVICE_DATA, frame);
            logger.debug("Sent MAX_STREAMS frame: maxStreams={}, bidirectional={}", maximumStreams, bidirectional);
        } catch (Exception e) {
            logger.error("Failed to send MAX_STREAMS frame", e);
        }
    }

    void sendMaxStreamDataFrame(long streamId, long maximumData) {
        PoolBuffer frame = StreamFrameWriter.encodeMaxStreamDataFrame(connection.getBufferPool(), streamId, maximumData);
        try {
            trySendData(serviceQueue, SERVICE_DATA, frame);
        } catch (Exception e) {
            logger.warn("Failed to send MAX_STREAM_DATA frame", e);
        }
    }

    void sendMaxDataFrame(long maximumData) {
        PoolBuffer frame = StreamFrameWriter.encodeMaxDataFrame(connection.getBufferPool(), maximumData);
        try {
            trySendData(serviceQueue, SERVICE_DATA, frame);
            logger.warn("Sent MAX_DATA frame: maxData={}", maximumData);
        } catch (Exception e) {
            logger.error("Failed to send MAX_DATA frame", e);
        }
    }

    void sendResetStreamFrame(long streamId, long errorCode, long finalSize) {
        PoolBuffer frame = StreamFrameWriter.encodeResetStreamFrame(connection.getBufferPool(), streamId, errorCode, finalSize);
        try {
            trySendData(serviceQueue, SERVICE_DATA, frame);
        } catch (Exception e) {
            logger.error("Failed to send RESET_STREAM frame", e);
        }
    }

    void sendStopSendingFrame(long streamId, long errorCode) {
        PoolBuffer frame = StreamFrameWriter.encodeStopSendingFrame(connection.getBufferPool(), streamId, errorCode);
        try {
            trySendData(serviceQueue, SERVICE_DATA, frame);
        } catch (Exception e) {
            logger.error("Failed to send STOP_SENDING frame", e);
        }
    }

    void sendStreamDataBlockedFrame(long streamId, long limit) {
        PoolBuffer frame = StreamFrameWriter.encodeStreamDataBlockedFrame(connection.getBufferPool(), streamId, limit);
        try {
            trySendData(serviceQueue, SERVICE_DATA, frame);
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
        PoolBuffer frame = StreamFrameWriter.encodeDataBlockedFrame(connection.getBufferPool(), limit);
        try {
            trySendData(serviceQueue, SERVICE_DATA, frame);
            logger.debug("Sent DATA_BLOCKED frame: limit={}", limit);
        } catch (Exception e) {
            logger.error("Failed to send DATA_BLOCKED frame", e);
        }
    }

    /**
     * Implementation of QuicStreamResponse for this manager.
     */
    public class QuicStreamResponseImpl implements QuicConnectionControl {
        private final StreamState streamState;

        private QuicStreamResponseImpl(StreamState streamState) {
            this.streamState = streamState;
        }

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
            StreamManager.this.closeStream(streamId, streamState, errorCode);
        }
    }
}

