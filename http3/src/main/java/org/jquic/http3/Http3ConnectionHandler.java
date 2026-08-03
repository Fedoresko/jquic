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
import org.jquic.quic.streamapi.QuicApplicationProtocolConnectionHandler;
import org.jquic.quic.streamapi.QuicConnectionControl;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.jquic.http3.qpack.QpackEncoder;
import org.jquic.http3.qpack.Decoder;
import org.jquic.http3.qpack.Encoder;
import org.jquic.http3.qpack.Header;
import org.jquic.http3.qpack.QpackException;

import org.jquic.http3.qpack.QpackBlockingManager;
import org.jquic.http3.qpack.QpackRequiredInsertCountException;

import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * HTTP/3 connection handler.
 * Manages HTTP/3 streams for a single QUIC connection.
 */
class Http3ConnectionHandler implements QuicApplicationProtocolConnectionHandler {
    private static final Logger logger = LoggerFactory.getLogger(Http3ConnectionHandler.class);

    private static final long SETTINGS_QPACK_MAX_TABLE_CAPACITY = 100;// 0x01;
    private static final long SETTINGS_MAX_FIELD_SECTION_SIZE = 0x06;
    private static final long SETTINGS_QPACK_BLOCKED_STREAMS = 0x07;

    private static final long DEFAULT_MAX_FIELD_SECTION_SIZE = 128 * 1024L;
    private static final long DEFAULT_QPACK_MAX_TABLE_CAPACITY = 4096L;
    private static final long DEFAULT_QPACK_BLOCKED_STREAMS = 100L;

    private final long connectionId;
    private final Http3RequestHandler requestHandler;
    private final ConcurrentHashMap<Long, Http3StreamContext> streams = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Long,  CompletableFuture<DataOutputStream>> futures = new ConcurrentHashMap<>();

    private final Map<Long, Http3ServerStreamRole> serverStreamRoles = new HashMap<>();
    private final ExecutorService vExecutor = Executors.newVirtualThreadPerTaskExecutor();

    private Long clientControlStreamId;
    private Long clientQpackEncoderStreamId;
    private Long clientQpackDecoderStreamId;

    /** When {@code true} QPACK encoding/decoding is used; otherwise plain-text framing. */
    private Encoder qpackEncoder;
    private Decoder qpackDecoder;
    private QpackBlockingManager qpackBlockingManager;

    private final long localQpackMaxTableCapacity = DEFAULT_QPACK_MAX_TABLE_CAPACITY;
    private final long localMaxBlockedStreams = DEFAULT_QPACK_BLOCKED_STREAMS;
    private final long localMaxFieldSectionSize = DEFAULT_MAX_FIELD_SECTION_SIZE;

    private long peerQpackMaxTableCapacity = 0; // Default until SETTINGS received
    private long peerMaxFieldSectionSize = 0; // Default until SETTINGS received

    private QuicConnectionControl connectionControl;

    public Http3ConnectionHandler(long connectionId, Http3RequestHandler requestHandler) {
        this.connectionId = connectionId;
        this.requestHandler = requestHandler;
    }

    @Override
    public void onConnectionEstablished(@NonNull QuicConnectionControl control) {
        this.connectionControl = control;
        try {
            // Trigger opening of mandatory streams.
            // RFC 9114 §6.2: Each endpoint MUST open at least one control stream.
            // RFC 9204 §4.2: QPACK requires two unidirectional streams in each direction.
            control.openStream(QuicConnectionControl.StreamType.Unidirectional);
            control.openStream(QuicConnectionControl.StreamType.Unidirectional);
            control.openStream(QuicConnectionControl.StreamType.Unidirectional);
        } catch (Exception e) {
            logger.error("Failed to trigger mandatory streams opening on connection {}", connectionId, e);
        }
    }

    private void putHttp3SettingsFrame(DataOutputStream out, Map<Long, Long> settings) throws IOException {
        // Calculate settings payload size
        int payloadSize = 0;
        for (Map.Entry<Long, Long> entry : settings.entrySet()) {
            payloadSize += QuicVarint.sizeOf(entry.getKey());
            payloadSize += QuicVarint.sizeOf(entry.getValue());
        }

        QuicVarint.write(out, 0x04); // Frame Type: SETTINGS
        QuicVarint.write(out, payloadSize);
        for (Map.Entry<Long, Long> entry : settings.entrySet()) {
            QuicVarint.write(out, entry.getKey());
            QuicVarint.write(out, entry.getValue());
        }
        out.flush();
    }

    @Override
    public void onNewServerStreamAllocated(long streamId, @NonNull DataOutputStream outputStream, QuicConnectionControl.StreamType streamType) {
        futures.put(streamId, CompletableFuture.supplyAsync(()->outputStream));

        Http3ServerStreamRole role = serverStreamRoles.get(streamId);

        if (role == null && streamType == QuicConnectionControl.StreamType.Unidirectional) {
            if (!serverStreamRoles.containsValue(Http3ServerStreamRole.CONTROL)) {
                serverStreamRoles.put(streamId, Http3ServerStreamRole.CONTROL);
                sendSettings(streamId, outputStream);
            } else if (!serverStreamRoles.containsValue(Http3ServerStreamRole.QPACK_ENCODER)) {
                serverStreamRoles.put(streamId, Http3ServerStreamRole.QPACK_ENCODER);
                qpackEncoder = Encoder.create(outputStream, peerQpackMaxTableCapacity, QpackEncoder.DEFAULT_INDEXING_THRESHOLD);
                try {
                    QuicVarint.write(outputStream, Http3ServerStreamRole.QPACK_ENCODER.getTypeValue());
                    outputStream.flush();
                } catch (IOException e) {
                    logger.error("Failed to initialize ENCODER stream");
                }
            } else if (!serverStreamRoles.containsValue(Http3ServerStreamRole.QPACK_DECODER)) {
                serverStreamRoles.put(streamId, Http3ServerStreamRole.QPACK_DECODER);
                qpackDecoder = Decoder.create(outputStream, localQpackMaxTableCapacity);
                qpackBlockingManager = new QpackBlockingManager(localMaxBlockedStreams, (sId, buffer) -> {
                    try {
                        return qpackDecoder.decodeHeaders(sId, buffer);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
                qpackDecoder.setUnblockedStreamListener(qpackBlockingManager::tryUnblockStreams);
                qpackBlockingManager.setUnblockedStreamListener(new Decoder.UnblockedStreamListener() {
                    @Override
                    public void onHeadersDecoded(long streamId, List<Header> headers) {
                        handleUnblockedHeaders(streamId, headers);
                    }

                    @Override
                    public void onDecodingError(long streamId, Exception e) {
                        handleUnblockedDecodingError(streamId, e);
                    }
                });
                try {
                    QuicVarint.write(outputStream, Http3ServerStreamRole.QPACK_DECODER.getTypeValue());
                    outputStream.flush();
                } catch (IOException e) {
                    logger.error("Failed to initialize DECODER stream");
                }
            }
        }
    }

    private void sendSettings(long streamId, @NonNull DataOutputStream outputStream) {
        try {
            QuicVarint.write(outputStream, Http3ServerStreamRole.CONTROL.getTypeValue());
            putHttp3SettingsFrame(outputStream, Map.of(
                    SETTINGS_MAX_FIELD_SECTION_SIZE, localMaxFieldSectionSize,
                    SETTINGS_QPACK_MAX_TABLE_CAPACITY, localQpackMaxTableCapacity,
                    SETTINGS_QPACK_BLOCKED_STREAMS, localMaxBlockedStreams
            ));
            outputStream.flush();
            logger.debug("Initialized mandatory server {} stream {} on connection {}", Http3ServerStreamRole.CONTROL, streamId, connectionId);
        } catch (IOException e) {
            logger.error("Failed to initialize mandatory server {} stream {} on connection {}", Http3ServerStreamRole.CONTROL, streamId, connectionId, e);
        }
    }

    private Map<Long, Long> parseSettingsPayload(byte[] payload) throws IOException {
        Map<Long, Long> settings = new HashMap<>();
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        while (buffer.hasRemaining()) {
            long id = QuicVarint.read(buffer);
            if (!buffer.hasRemaining()) {
                throw new IOException("Truncated SETTINGS frame");
            }
            long value = QuicVarint.read(buffer);
            settings.put(id, value);
        }
        return settings;
    }

    private void handleSettings(Map<Long, Long> settings) {
        if (settings.containsKey(SETTINGS_QPACK_MAX_TABLE_CAPACITY)) {
            peerQpackMaxTableCapacity = settings.get(SETTINGS_QPACK_MAX_TABLE_CAPACITY);
            if (qpackEncoder != null) {
                qpackEncoder.setDynamicTableCapacity(peerQpackMaxTableCapacity);
            }
        }
        if (settings.containsKey(SETTINGS_QPACK_BLOCKED_STREAMS)) {
            long peerMaxBlockedStreams = settings.get(SETTINGS_QPACK_BLOCKED_STREAMS);
            if (qpackEncoder != null) {
                qpackEncoder.setMaxBlockedStreams(peerMaxBlockedStreams);
            }
        }
        if (settings.containsKey(SETTINGS_MAX_FIELD_SECTION_SIZE)) {
            peerMaxFieldSectionSize = settings.get(SETTINGS_MAX_FIELD_SECTION_SIZE);
        }
        logger.debug("Received SETTINGS on connection {}: {}", connectionId, settings);
    }

    @Override
    public void onNewClientStreamAllocated(long streamId, @NonNull QuicConnectionControl control, DataOutputStream outputStream, QuicConnectionControl.StreamType streamType) {
        boolean isUnidirectional = (streamId & 0x02) != 0;
        boolean isServerInitiated = (streamId & 0x01) != 0;

        if (!isUnidirectional) {
            if (isServerInitiated) {
                try {
                    control.closeConnection(Http3Server.H3_STREAM_CREATION_ERROR, "Server-initiated bidirectional streams are reserved");
                } catch (Exception e) {
                    logger.error("Failed to close connection after receiving reserved stream", e);
                }
            } else {
                Http3StreamContext context = new Http3StreamContext(Http3ClientStreamRole.REQUEST);
                streams.put(streamId, context);
                futures.put(streamId, CompletableFuture.supplyAsync(()->outputStream, vExecutor));
                logger.debug("New HTTP/3 request stream {} allocated on connection {}", streamId, connectionId);
            }
        } else {
            if (isServerInitiated) {
                try {
                    control.closeConnection(Http3Server.H3_STREAM_CREATION_ERROR, "Clients cannot initiate streams in server-initiated stream ID space");
                } catch (Exception e) {
                    logger.error("Failed to close connection after receiving reserved stream", e);
                }
                return;
            }
            // Unidirectional stream (remote peer opened it)
            // Wait for first byte to determine role.
            Http3StreamContext context = new Http3StreamContext(null);
            streams.put(streamId, context);
            logger.debug("New unidirectional stream {} allocated on connection {}, waiting for type byte", streamId, connectionId);
        }
    }

    @Override
    public void onStreamDataReceived(long streamId, @NonNull QuicConnectionControl response,
                                     byte[] data, boolean isLastData, @Nullable Long errorCode) {
        Http3StreamContext context = streams.get(streamId);
        if (context == null) {
            logger.warn("Received data for unknown stream {} on connection {} {}", streamId, connectionId, HexFormat.of().formatHex(data));
            return;
        }

        if (errorCode != null) {
            logger.warn("Stream {} on connection {} reset with error code {}", 
                       streamId, connectionId, errorCode);
            finishStream(streamId);
            return;
        }
        logger.warn("Received data for stream {} on connection {} last {} data {}", streamId, connectionId, isLastData, HexFormat.of().formatHex(data));

        context.appendData(data);

        // Unidirectional stream type identification (RFC 9114 §6.2)
        if (context.getRole() == null) {
            Http3ClientStreamRole role = getHttp3ClientStreamRole(streamId, response, context.tryReadStreamType());
            if (role == null) {
                logger.error("Failed to parse stream role for stream {} on connection {}", streamId, connectionId);
                return;
            }
            context.setRole(role);
        }

        switch (context.getRole()) {
            case Http3ClientStreamRole.REQUEST -> handleRequestStream(streamId, response, isLastData, context);
            case Http3ClientStreamRole.CONTROL -> handleControlStream(streamId, response, data, isLastData, context);
            case Http3ClientStreamRole.QPACK_ENCODER ->
                    handleEncoderStream(streamId, response, data, isLastData, context);
            case Http3ClientStreamRole.QPACK_DECODER ->
                    handleDecoderStream(streamId, response, data, isLastData, context);
            case Http3ClientStreamRole.GREASE -> {
                logger.debug("Grease stream {} data received ({} bytes) - discarding", streamId, data.length);
                handleEnding(streamId, data, isLastData, context);
            }
            case Http3ClientStreamRole.UNKNOWN -> handleEnding(streamId, data, isLastData, context);
            default -> throw new IllegalStateException("Unexpected value: " + context.getRole());
        }
    }

    private void handleEnding(long streamId, byte[] data, boolean isLastData, Http3StreamContext context) {
        if (isLastData) finishStream(streamId);
        context.consume(data.length);
    }

    private void handleDecoderStream(long streamId, @NonNull QuicConnectionControl response, byte[] data, boolean isLastData, Http3StreamContext context) {
        // QPACK decoder stream - buffer acknowledgements; processing not yet implemented.
        logger.debug("QPACK decoder stream {} data received ({} bytes) - processing",
                streamId, data.length);
        qpackEncoder.onDecoderData(ByteBuffer.wrap(data));
        if (isLastData) {
            try {
                response.closeConnection(Http3Server.H3_CLOSED_CRITICAL_STREAM, "QPACK decoder stream closed by peer");
            } catch (Exception e) {
                logger.error("Failed to close connection after QPACK decoder closure", e);
            }
        }

        handleEnding(streamId, data, isLastData, context);
    }

    private void handleEncoderStream(long streamId, @NonNull QuicConnectionControl response, byte[] data, boolean isLastData, Http3StreamContext context) {
        // QPACK encoder stream - buffer instructions; processing not yet implemented.
        logger.debug("QPACK encoder stream {} data received ({} bytes) - processing",
                streamId, data.length);
        qpackDecoder.onEncoderData(ByteBuffer.wrap(data));
        if (isLastData) {
            try {
                response.closeConnection(Http3Server.H3_CLOSED_CRITICAL_STREAM, "QPACK encoder stream closed by peer");
            } catch (Exception e) {
                logger.error("Failed to close connection after QPACK encoder closure", e);
            }
            return;
        }

        // RFC 9204 §4.2: QPACK streams do not use HTTP/3 framing.
        // Just discard the raw bytes for now.
        handleEnding(streamId, data, isLastData, context);
    }

    private void handleControlStream(long streamId, @NonNull QuicConnectionControl response, byte[] data, boolean isLastData, Http3StreamContext context) {
        // Control stream - buffer data; control frame processing is not yet implemented.
        logger.debug("Control stream {} data received ({} bytes) - processing not yet implemented",
                streamId, data.length);

        // RFC 9114 §6.2.1: Control stream MUST NOT be closed.
        if (isLastData) {
            try {
                response.closeConnection(Http3Server.H3_CLOSED_CRITICAL_STREAM, "Control stream closed by peer");
            } catch (Exception e) {
                logger.error("Failed to close connection after control stream closure", e);
            }
            finishStream(streamId);
            return;
        }

        // Consume frames to avoid H3_FRAME_ERROR on cleanup
        try {
            Http3StreamContext.ParsedFrame frame;
            while ((frame = context.pollFrame()) != null) {
                if (!context.firstFrameReceived) {
                    context.firstFrameReceived = true;
                    if (frame.type() != 0x04 /* SETTINGS */) {
                        logger.warn("First frame on control stream {} is not SETTINGS (type 0x{}) - H3_MISSING_SETTINGS",
                                streamId, Long.toHexString(frame.type()));
                        response.closeConnection(Http3Server.H3_MISSING_SETTINGS, "First frame not SETTINGS");
                        return;
                    }
                    Map<Long, Long> settings = parseSettingsPayload(frame.payload());
                    handleSettings(settings);
                } else {
                    if (frame.type() == 0x04 /* SETTINGS */) {
                        // RFC 9114 §7.2.4: Only one SETTINGS frame is allowed.
                        logger.warn("Duplicate SETTINGS frame on control stream {} - H3_SETTINGS_ERROR", streamId);
                        response.closeConnection(Http3Server.H3_SETTINGS_ERROR, "Duplicate SETTINGS frame");
                        return;
                    }
                }

                if (frame.type() == 0x00 /* DATA */ || frame.type() == 0x01 /* HEADERS */) {
                    // RFC 9114 §7.2.1, §7.2.2: DATA and HEADERS MUST NOT be sent on the control stream.
                    logger.warn("Forbidden frame type 0x{} received on control stream {} (connection {})",
                            Long.toHexString(frame.type()), streamId, connectionId);
                    response.closeConnection(Http3Server.H3_FRAME_UNEXPECTED, "DATA/HEADERS on control stream");
                    return;
                }
                // Handle other frames like GOAWAY if implemented
            }
        } catch (Exception e) {
            logger.error("Failed to process control stream frames on stream " + streamId, e);
            try {
                response.closeConnection(Http3Server.H3_FRAME_ERROR, "Malformed frame on control stream");
            } catch (Exception closeEx) {
                logger.error("Failed to close connection after control stream error", closeEx);
            }
        }
    }

    private void handleUnblockedHeaders(long streamId, List<Header> headers) {
        Http3StreamContext context = streams.get(streamId);
        if (context == null) return;

        Map<String, String> headersMap = headers.stream()
                .collect(Collectors.toMap(Header::name, Header::value, (v1, _) -> v1));

        String method = headersMap.getOrDefault(":method", "GET");
        String path = headersMap.getOrDefault(":path", "/");
        Long contentLength = Optional.ofNullable(headersMap.get(":content-length")).map(Long::valueOf).orElse(null);

        Http3Request request = new Http3Request(connectionId, method, path, contentLength);
        context.setRequest(request);
        dispatchRequest(streamId, context);
    }

    private void handleUnblockedDecodingError(long streamId, Exception e) {
        logger.warn("QPACK decoding failed on unblocked stream {} (connection {}): {}",
                streamId, connectionId, e.getMessage());
        if (e instanceof QpackException qe) {
            try {
                if (connectionControl != null) {
                    connectionControl.closeConnection(qe.getErrorCode(), qe.getMessage());
                }
            } catch (Exception ex) {
                logger.error("Failed to close connection after QPACK error", ex);
            }
        }
    }

    private void dispatchRequest(long streamId, Http3StreamContext context) {
        Http3Request request = context.getRequest();
        if (request == null) return;

        if (request.getContentLength() == null) {
            context.setRequestState(Http3StreamContext.RequestProcessingState.WAITING_FOR_FIN);
        } else if (request.getContentLength() == 0) {
            context.setRequestState(Http3StreamContext.RequestProcessingState.RESPONSE_SENDING);
            CompletableFuture<DataOutputStream> responseFuture = futures.get(streamId);
            Http3Response response = requestHandler.handleRequest(request);
            putResponse(streamId, responseFuture, response)
                    .thenAccept(_ -> {
                        context.setRequestState(Http3StreamContext.RequestProcessingState.FINISHED);
                        finishStream(streamId);
                    });
        } else {
            context.setRequestState(Http3StreamContext.RequestProcessingState.WAITING_FOR_BODY);
        }
    }

    private void handleRequestStream(long streamId, @NonNull QuicConnectionControl response, boolean isLastData, Http3StreamContext context) {
        // Client-initiated bidirectional request stream.
        // Use a state machine to dispatch the request as soon as headers arrive,
        // then feed body DATA frames incrementally, without waiting for stream FIN.
        try {
            Http3StreamContext.ParsedFrame frame;
            while ((frame = context.pollFrame()) != null) {
                if (frame.type() == 0x01 /* HEADERS */ &&
                        context.getRequestState() == Http3StreamContext.RequestProcessingState.INITIAL) {
                    // Parse and dispatch the request immediately on first HEADERS frame.
                    try {
                        ByteBuffer payload = frame.payloadAsBuffer();
                        if (checkHeadersSize(streamId, response, payload.remaining())) {
                            List<Header> decoded = qpackDecoder.decodeHeaders(streamId, payload);
                            if (decoded != null) {
                                Map<String, String> headersMap = decoded.stream()
                                        .collect(Collectors.toMap(Header::name, Header::value, (v1, _) -> v1));

                                String method = headersMap.getOrDefault(":method", "GET");
                                String path = headersMap.getOrDefault(":path", "/");
                                Long contentLength = Optional.ofNullable(headersMap.get(":content-length")).map(Long::valueOf).orElse(null);

                                Http3Request request = new Http3Request(connectionId, method, path, contentLength);
                                context.setRequest(request);
                                dispatchRequest(streamId, context);
                            }
                        }
                    } catch (QpackRequiredInsertCountException e) {
                        if (qpackBlockingManager != null) {
                            qpackBlockingManager.blockStream(streamId, e.getFrame(), e.getRequiredInsertCount());
                        } else {
                            throw new IOException("Stream blocked but no blocking manager available", e);
                        }
                    }
                } else if (frame.type() == 0x00 /* DATA */ ) {
                    // DATA frame body chunk - accumulate for response (could be streamed further).
                    if (context.getRequest() != null &&  context.getRequestState() != Http3StreamContext.RequestProcessingState.RESPONSE_SENDING) {
                        context.getRequest().appendBody(new String(frame.payload()));
                        context.readBodyBytes += frame.payload().length;
                        if (context.getRequestState() == Http3StreamContext.RequestProcessingState.WAITING_FOR_BODY) {
                            if (context.readBodyBytes == context.getRequest().getContentLength()) {
                                Http3Response httpResponse = requestHandler.handleRequest(context.getRequest());
                                // Send the response immediately - do not wait for stream FIN.
                                logger.debug("Sending HTTP/3 response on stream {} (connection {}) immediately after HEADERS",
                                        streamId, connectionId);
                                futures.computeIfPresent(streamId, (id, future) -> putResponse(id, future, httpResponse));
                                context.setRequestState(Http3StreamContext.RequestProcessingState.RESPONSE_SENDING);
                            }
                        }
                    }
                } else if (frame.type() == 0x04 /* SETTINGS */) {
                    // RFC 9114 §7.2.4: SETTINGS MUST ONLY be sent on the control stream.
                    logger.warn("SETTINGS frame received on request stream {} (connection {}) - H3_FRAME_UNEXPECTED",
                            streamId, connectionId);
                    response.closeConnection(Http3Server.H3_FRAME_UNEXPECTED, "SETTINGS frame received on request stream");
                    return;
                }
                // Other frame types (CANCEL_PUSH, GOAWAY, etc.) are ignored on request streams (RFC 9114 §7.1)
            }

            if (isLastData) {
                // RFC 9114 §4.1: validate stream state on FIN before cleaning up.
                if (context.hasUnconsumedData()) {
                    logger.warn("Stream {} FIN with truncated frame data (connection {}) - H3_FRAME_ERROR",
                            streamId, connectionId);
                    response.closeStream(streamId, Http3Server.H3_FRAME_ERROR); // H3_MESSAGE_ERROR
                    finishStream(streamId);
                } else
                    if (context.getRequestState() == Http3StreamContext.RequestProcessingState.INITIAL) {
                    logger.warn("Stream {} FIN received without a HEADERS frame (connection {}) - H3_MESSAGE_ERROR",
                            streamId, connectionId);
                    response.closeStream(streamId, Http3Server.H3_MESSAGE_ERROR); // H3_MESSAGE_ERROR
                    finishStream(streamId);
                } else

                    if (context.getRequestState() == Http3StreamContext.RequestProcessingState.WAITING_FOR_FIN) {
                    Http3Response httpResponse = requestHandler.handleRequest(context.getRequest());
                    // Send the response immediately - do not wait for stream FIN.
                    logger.debug("Sending HTTP/3 response on stream {} (connection {}) immediately after HEADERS",
                            streamId, connectionId);
                    futures.computeIfPresent(streamId, (id, future) -> putResponse(id, future, httpResponse));
                    finishStream(streamId);
                } else {
                    // Clean FIN - response was already sent; just remove stream context.
                    logger.debug("Stream {} FIN received cleanly, removing context (connection {})",
                            streamId, connectionId);
                    finishStream(streamId);
                }
                context.setRequestState(Http3StreamContext.RequestProcessingState.FINISHED);
            }
        } catch (Exception e) {
            logger.error("Failed to process HTTP/3 request on stream " + streamId, e);
            try {
                response.closeStream(streamId, Http3Server.H3_GENERAL_PROTOCOL_ERROR); // H3_GENERAL_PROTOCOL_ERROR
            } catch (Exception closeEx) {
                logger.error("Failed to close stream after error", closeEx);
            }
            finishStream(streamId);
        }
    }

    private boolean checkHeadersSize(long streamId, QuicConnectionControl response, long encodedSize) {
        if (encodedSize > localMaxFieldSectionSize) {
            logger.warn("Incoming encoded headers size {} exceeds local MAX_FIELD_SECTION_SIZE {} on stream {}",
                    encodedSize, localMaxFieldSectionSize, streamId);
            try {
                // Close stream using RESET_STREAM and STOP_SENDING with code H3_REQUEST_CANCELLED
                response.closeStream(streamId, Http3Server.H3_REQUEST_CANCELLED);
                
                // Respond with http code (431 Request Header Fields Too Large)
                CompletableFuture<DataOutputStream> responseFuture = futures.get(streamId);
                if (responseFuture != null) {
                    responseFuture.thenAccept(out -> {
                        try {
                            Http3Response errorResponse = new Http3Response(431, "text/plain",
                                    "Request Header Fields Too Large".getBytes(), List.of());
                            putResponse(streamId, CompletableFuture.completedFuture(out), errorResponse)
                                    .thenAccept(_ -> finishStream(streamId));
                        } catch (Exception e) {
                            logger.error("Failed to send 431 response", e);
                        }
                    });
                }
            } catch (Exception e) {
                logger.error("Error handling header size limit", e);
            }
            return false;
        }
        return true;
    }

    private void finishStream(long streamId) {
        if (qpackBlockingManager != null) {
            qpackBlockingManager.cancelStream(streamId);
        }
        if (qpackDecoder != null) {
            qpackDecoder.cancelStream(streamId);
        }
        CompletableFuture<DataOutputStream> future = futures.remove(streamId);
        if (future != null) {
            future.thenAcceptAsync(dataOutputStream -> {
                try {
                    dataOutputStream.close();
                } catch (IOException _) {}
            }, vExecutor);
        }
        streams.remove(streamId);
    }

    private @Nullable Http3ClientStreamRole getHttp3ClientStreamRole(long streamId, @NonNull QuicConnectionControl response, Long type) {
        if  (type == null) return null;

        // Since this is a server-side handler, we only expect client-initiated unidirectional streams.
        // In HTTP/3, servers never receive data on server-initiated streams.
        Http3ClientStreamRole role = Http3ClientStreamRole.fromStreamType(type);

        // RFC 9114 §6.2: Each endpoint MUST open at least one control stream.
        // Receipt of a second control stream MUST be treated as H3_STREAM_CREATION_ERROR.
        // RFC 9204 §4.2: Multiple QPACK encoder/decoder streams MUST be treated as H3_STREAM_CREATION_ERROR.
        if (role == Http3ClientStreamRole.CONTROL) {
            if (clientControlStreamId != null) {
                try {
                    response.closeConnection(Http3Server.H3_STREAM_CREATION_ERROR, "Multiple control streams received");
                } catch (Exception e) {
                    logger.error("Failed to close connection after receiving multiple control streams", e);
                }
                return null;
            }
            clientControlStreamId = streamId;
        } else if (role == Http3ClientStreamRole.QPACK_ENCODER) {
            if (clientQpackEncoderStreamId != null) {
                try {
                    response.closeConnection(Http3Server.H3_STREAM_CREATION_ERROR, "Multiple QPACK encoder streams received");
                } catch (Exception e) {
                    logger.error("Failed to close connection after receiving multiple QPACK encoder streams", e);
                }
                return null;
            }
            clientQpackEncoderStreamId = streamId;
        } else if (role == Http3ClientStreamRole.QPACK_DECODER) {
            if (clientQpackDecoderStreamId != null) {
                try {
                    response.closeConnection(Http3Server.H3_STREAM_CREATION_ERROR, "Multiple QPACK decoder streams received");
                } catch (Exception e) {
                    logger.error("Failed to close connection after receiving multiple QPACK decoder streams", e);
                }
                return null;
            }
            clientQpackDecoderStreamId = streamId;
        } else if (role == Http3ClientStreamRole.UNKNOWN) {
            logger.debug("Unknown unidirectional stream type {} on stream {} (connection {}) - ignoring",
                    type, streamId, connectionId);
        }

        logger.debug("Unidirectional stream {} on connection {} identified as {}",
                streamId, connectionId, role);
        return role;
    }

    @Override
    public void onDatagramReceived(byte[] data, @NonNull QuicConnectionControl control) {
        //No datagrams in Http3;
    }

    @Override
    public void setOutgoingDatagramStream(@NonNull DataOutputStream outputStream) {
        //No datagrams in Http3;
    }

    @Override
    public void onConnectionClose() {
        futures.clear();
    }

    /**
     * Encodes HTTP/3 response to raw bytes.
     * Uses QPACK header compression when {@code useQpack} is enabled,
     * otherwise falls back to the simplified plain-text format.
     */
    private CompletableFuture<DataOutputStream> putResponse(long streamId, CompletableFuture<DataOutputStream> responseFuture, Http3Response response) {
        byte[] body        = response.getBody();

        List<Map.Entry<String, String>> headers = new ArrayList<>(List.of(
                new AbstractMap.SimpleEntry<>(":status", String.valueOf(response.getStatusCode())),
                new AbstractMap.SimpleEntry<>("content-type", response.getContentType()),
                new AbstractMap.SimpleEntry<>("content-length", String.valueOf(body.length))));

        headers.addAll(response.getHeaders());
        List<Header> qHeaders = headers.stream().map(e -> new Header(e.getKey(), e.getValue())).toList();

        // Local: if our headers exceed client's limit only log warning.
        if (peerMaxFieldSectionSize > 0) {
            long totalSize = 0;
            for (Header h : qHeaders) {
                totalSize += h.name().length() + h.value().length() + 32;
            }
            if (totalSize > peerMaxFieldSectionSize) {
                logger.warn("Outgoing headers size {} exceeds peer's MAX_FIELD_SECTION_SIZE {} on stream {}",
                        totalSize, peerMaxFieldSectionSize, streamId);
            }
        }

        ByteBuffer headerBlock;
        try {
            headerBlock = qpackEncoder.encodeHeaders(streamId, qHeaders).position(0);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return responseFuture.thenApplyAsync((outputStream) -> {
            try {
                // HTTP/3 framing: each frame = type (varint) + length (varint) + payload
                putHttp3Frame(outputStream, 0x01, headerBlock);
                putHttp3Frame(outputStream, 0x00, body);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return outputStream;
        }, vExecutor);
    }

    /**
     * Builds a minimal HTTP/3 frame with the given type and payload.
     * Uses single-byte varints (sufficient for payloads up to 63 bytes in type/length).
     */
    private void putHttp3Frame(DataOutputStream outputStream, int frameType, byte[] payload) throws IOException {
        // Encode type and length as QUIC-style varints (1-byte form for values < 64)
        QuicVarint.write(outputStream, frameType);
        QuicVarint.write(outputStream, payload.length);
        outputStream.write(payload);
    }

    private void putHttp3Frame(DataOutputStream outputStream, int frameType, ByteBuffer payload) throws IOException {
        // Encode type and length as QUIC-style varints (1-byte form for values < 64)
        QuicVarint.write(outputStream, frameType);
        QuicVarint.write(outputStream, payload.remaining());
        outputStream.write(payload.array(), payload.position(), payload.remaining());
    }

    /**
     * Context for a single HTTP/3 stream.
     */
    private static class Http3StreamContext {

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

        /** HTTP/3-level role of this stream. */
        private @Nullable Object role;

        // ---- request state machine ----
        private RequestProcessingState requestState = RequestProcessingState.INITIAL;
        private Http3Request request;
        private boolean firstFrameReceived = false;

        public int readBodyBytes = 0;

        Http3StreamContext(@Nullable Object role) {
            this.role = role;
        }

        @Nullable Object getRole() {
            return role;
        }

        void setRole(@NonNull Object role) {
            this.role = role;
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
        @Nullable Long tryReadStreamType() {
            Long type = peekVarint(0);
            if (type != null) {
                consume(QuicVarint.sizeOf(type));
                return type;
            }
            return null;
        }

        /**
         * Tries to parse the next complete HTTP/3 frame from the buffer.
         */
        @Nullable ParsedFrame pollFrame() {
            Long type = peekVarint(0);
            if (type == null) return null;
            int typeLen = QuicVarint.sizeOf(type);
            Long length = peekVarint(typeLen);
            if (length == null) return null;
            int lengthLen = QuicVarint.sizeOf(length);

            if (bufferedBytes < typeLen + lengthLen + length) return null;

            // RFC 9114 §7.2.4: SETTINGS MUST be the first frame.
            // We check this here to easily detect it before consuming.
            // But role-specific validation is better done in onStreamDataReceived.

            consume(typeLen + lengthLen);
            byte[] payload = new byte[length.intValue()];
            int pos = 0;
            while (pos < payload.length && !chunks.isEmpty()) {
                ByteBuffer chunk = chunks.peek();
                int toCopy = Math.min(chunk.remaining(), payload.length - pos);
                chunk.get(payload, pos, toCopy);
                pos += toCopy;
                bufferedBytes -= toCopy;
                if (chunk.remaining() == 0) chunks.poll();
            }
            return new ParsedFrame(type, payload);
        }
    }
}

