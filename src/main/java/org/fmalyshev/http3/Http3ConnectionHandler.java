package org.fmalyshev.http3;

import org.fmalyshev.quic.QuicVarint;
import org.fmalyshev.quic.streamapi.QuicApplicationProtocolConnectionHandler;
import org.fmalyshev.quic.streamapi.QuicStreamException;
import org.fmalyshev.quic.streamapi.QuicStreamResponse;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tech.kwik.qpack.Decoder;
import tech.kwik.qpack.Encoder;

import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * HTTP/3 connection handler.
 * Manages HTTP/3 streams for a single QUIC connection.
 */
class Http3ConnectionHandler implements QuicApplicationProtocolConnectionHandler {
    private static final Logger logger = LoggerFactory.getLogger(Http3ConnectionHandler.class);

    private final long connectionId;
    private final Http3RequestHandler requestHandler;
    private final ConcurrentHashMap<Long, Http3StreamContext> streams = new ConcurrentHashMap<>();

    /** When {@code true} QPACK encoding/decoding is used; otherwise plain-text framing. */
    private final Encoder qpackEncoder = Encoder.newBuilder().build();
    private final Decoder qpackDecoder = Decoder.newBuilder().build();


    public Http3ConnectionHandler(long connectionId, Http3RequestHandler requestHandler) {
        this.connectionId = connectionId;
        this.requestHandler = requestHandler;
    }

    @Override
    public void onNewStreamAllocated(long streamId, @NonNull QuicStreamResponse response, 
                                    boolean isServer, QuicStreamResponse.StreamType streamType) {
        // Bidirectional streams are always client-initiated request streams (RFC 9114 §6.1).
        // Unidirectional streams carry their HTTP/3 role in the first stream-type varint,
        // so we mark them as UNKNOWN until we read those bytes.
        Http3StreamRole initialRole = (streamType == QuicStreamResponse.StreamType.Bidirectional)
                ? Http3StreamRole.REQUEST
                : Http3StreamRole.UNKNOWN;

        logger.debug("New HTTP/3 stream {} allocated on connection {} (server={}, quicType={}, h3Role={})",
                    streamId, connectionId, isServer, streamType, initialRole);

        Http3StreamContext context = new Http3StreamContext(streamId, initialRole);
        streams.put(streamId, context);
    }

    @Override
    public void onStreamDataReceived(long streamId, @NonNull QuicStreamResponse response, 
                                     byte[] data, boolean isLastData, @Nullable Long errorCode) {
        Http3StreamContext context = streams.get(streamId);
        if (context == null) {
            logger.warn("Received data for unknown stream {} on connection {}", streamId, connectionId);
            return;
        }

        if (errorCode != null) {
            logger.warn("Stream {} on connection {} reset with error code {}", 
                       streamId, connectionId, errorCode);
            streams.remove(streamId);
            return;
        }

        // Append data to stream buffer
        context.appendData(data);

        // For unidirectional streams whose role is not yet known, try to determine it
        // from the leading stream-type varint (RFC 9114 §6.2).
        if (context.getRole() == Http3StreamRole.UNKNOWN) {
            context.tryDetermineRole();
            logger.debug("Unidirectional stream {} on connection {} identified as {}",
                    streamId, connectionId, context.getRole());
        }

        switch (context.getRole()) {
            case REQUEST -> {
                // Client-initiated bidirectional request stream.
                // Use a state machine to dispatch the request as soon as headers arrive,
                // then feed body DATA frames incrementally, without waiting for stream FIN.
                try {
                    Http3StreamContext.ParsedFrame frame;
                    while ((frame = context.pollFrame()) != null) {
                        if (frame.type() == 0x01 /* HEADERS */ &&
                                context.getRequestState() == Http3StreamContext.RequestProcessingState.INITIAL) {
                            // Parse and dispatch the request immediately on first HEADERS frame.
                            Http3Request request = parseRequestQpack(frame.payloadAsBuffer());
                            context.setRequest(request);
                            if (request != null) {
                                if (request.getContentLength() == null) {
                                    context.setRequestState(Http3StreamContext.RequestProcessingState.WAITING_FOR_FIN);
                                } else if (request.getContentLength() == 0) {
                                    logger.debug("Dispatching HTTP/3 request on stream {} (connection {}) after HEADERS frame",
                                            streamId, connectionId);
                                    Http3Response httpResponse = requestHandler.handleRequest(request);
                                    // Send the response immediately — do not wait for stream FIN.
                                    logger.debug("Sending HTTP/3 response on stream {} (connection {}) immediately after HEADERS",
                                            streamId, connectionId);
                                    response.sendData(streamId, buffer -> putResponse(buffer, httpResponse), true);
                                    context.setRequestState(Http3StreamContext.RequestProcessingState.RESPONSE_SENT);
                                } else {
                                    context.setRequestState(Http3StreamContext.RequestProcessingState.WAITING_FOR_BODY);
                                }
                            }
                        } else if (frame.type() == 0x00 /* DATA */ ) {
                            // DATA frame body chunk — accumulate for response (could be streamed further).
                            if (context.getRequest() != null &&  context.getRequestState() != Http3StreamContext.RequestProcessingState.RESPONSE_SENT) {
                                context.getRequest().appendBody(new String(frame.payload()));
                                context.readBodyBytes += frame.payload().length;
                                if (context.getRequestState() == Http3StreamContext.RequestProcessingState.WAITING_FOR_BODY) {
                                    if (context.readBodyBytes == context.getRequest().getContentLength()) {
                                        Http3Response httpResponse = requestHandler.handleRequest(context.getRequest());
                                        // Send the response immediately — do not wait for stream FIN.
                                        logger.debug("Sending HTTP/3 response on stream {} (connection {}) immediately after HEADERS",
                                                streamId, connectionId);
                                        response.sendData(streamId, buffer -> putResponse(buffer, httpResponse), true);
                                        context.setRequestState(Http3StreamContext.RequestProcessingState.RESPONSE_SENT);
                                    }
                                }
                            }
                        }
                        // Other frame types (CANCEL_PUSH, SETTINGS, etc.) are ignored on request streams.
                    }

                    if (isLastData) {
                        // RFC 9114 §4.1: validate stream state on FIN before cleaning up.
                        if (context.hasUnconsumedData()) {
                            logger.warn("Stream {} FIN with truncated frame data (connection {}) — H3_FRAME_ERROR",
                                    streamId, connectionId);
                            response.closeStream(streamId, Http3Server.H3_FRAME_ERROR); // H3_MESSAGE_ERROR
                        } else if (context.getRequestState() == Http3StreamContext.RequestProcessingState.INITIAL) {
                            logger.warn("Stream {} FIN received without a HEADERS frame (connection {}) — H3_MESSAGE_ERROR",
                                    streamId, connectionId);
                            response.closeStream(streamId, Http3Server.H3_MESSAGE_ERROR); // H3_MESSAGE_ERROR
                        } else if (context.getRequestState() == Http3StreamContext.RequestProcessingState.WAITING_FOR_FIN) {
                            Http3Response httpResponse = requestHandler.handleRequest(context.getRequest());
                            // Send the response immediately — do not wait for stream FIN.
                            logger.debug("Sending HTTP/3 response on stream {} (connection {}) immediately after HEADERS",
                                    streamId, connectionId);
                            response.sendData(streamId, buffer -> putResponse(buffer, httpResponse), true);
                            context.setRequestState(Http3StreamContext.RequestProcessingState.RESPONSE_SENT);
                        } else {
                            // Clean FIN — response was already sent; just remove stream context.
                            logger.debug("Stream {} FIN received cleanly, removing context (connection {})",
                                    streamId, connectionId);
                        }
                        streams.remove(streamId);
                    }
                } catch (Exception e) {
                    logger.error("Failed to process HTTP/3 request on stream " + streamId, e);
                    try {
                        response.closeStream(streamId, Http3Server.H3_GENERAL_PROTOCOL_ERROR); // H3_GENERAL_PROTOCOL_ERROR
                    } catch (Exception closeEx) {
                        logger.error("Failed to close stream after error", closeEx);
                    }
                    streams.remove(streamId);
                }
            }
            case CONTROL -> {
                // Control stream — buffer data; control frame processing is not yet implemented.
                logger.debug("Control stream {} data received ({} bytes) — processing not yet implemented",
                        streamId, data.length);
            }
            case QPACK_ENCODER -> {
                // QPACK encoder stream — buffer instructions; processing not yet implemented.
                logger.debug("QPACK encoder stream {} data received ({} bytes) — processing not yet implemented",
                        streamId, data.length);
            }
            case QPACK_DECODER -> {
                // QPACK decoder stream — buffer acknowledgements; processing not yet implemented.
                logger.debug("QPACK decoder stream {} data received ({} bytes) — processing not yet implemented",
                        streamId, data.length);
            }
            case PUSH -> {
                // Push stream — buffer data; push processing not yet implemented.
                logger.debug("Push stream {} data received ({} bytes) — processing not yet implemented",
                        streamId, data.length);
            }
            case UNKNOWN -> {
                // Not enough bytes to determine stream type yet; wait for more data.
                logger.debug("Stream {} on connection {} type still unknown, waiting for more data",
                        streamId, connectionId);
            }
        }
    }

    /**
     * Parses an HTTP/3 request that uses QPACK-encoded headers (RFC 9204).
     *
     * <p>The incoming {@code data} is expected to be the payload of an HTTP/3
     * HEADERS frame (frame type 0x01), i.e. a QPACK header block.
     */
    private Http3Request parseRequestQpack(ByteBuffer data) {
        try {
            Map<String, String> headers = qpackDecoder.decodeStream(new ByteArrayInputStream(data.array(), data.position(), data.remaining())).stream()
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

            String method = headers.getOrDefault(":method", "GET");
            String path = headers.getOrDefault(":path", "/");
            Long contentLength = Optional.ofNullable(headers.getOrDefault(":content-length", null)).map(Long::valueOf).orElse(null);
            data.position(data.limit());
            return new Http3Request(connectionId, method, path, contentLength);
        } catch (IOException e) {
            logger.warn("QPACK decoding failed on stream (connection {})",
                    connectionId, e.getMessage());
            return null;
        }
    }

    /**
     * Encodes HTTP/3 response to raw bytes.
     * Uses QPACK header compression when {@code useQpack} is enabled,
     * otherwise falls back to the simplified plain-text format.
     */
    private void putResponse(DataOutputStream outputStream, Http3Response response) {
        byte[] body        = response.getBody();

        List<Map.Entry<String, String>> headers = new ArrayList<>(List.of(
                new AbstractMap.SimpleEntry<>(":status", String.valueOf(response.getStatusCode())),
                new AbstractMap.SimpleEntry<>("content-type", response.getContentType()),
                new AbstractMap.SimpleEntry<>("content-length", String.valueOf(body.length))));

        headers.addAll(response.getHeaders());

        ByteBuffer headerBlock = qpackEncoder.compressHeaders(headers).position(0);

        try {
            // HTTP/3 framing: each frame = type (varint) + length (varint) + payload
            putHttp3Frame(outputStream, 0x01, headerBlock);
            putHttp3Frame(outputStream, 0x00, body);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
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

        /**
         * State machine for processing an HTTP/3 request stream.
         *
         * <ul>
         *   <li>{@code WAITING_FOR_BODY} – .</li>
         *   <li>{@code HEADERS_DISPATCHED} – HEADERS were parsed and the request was handed to the
         *       handler; DATA frames (body chunks) may still arrive.</li>
         *   <li>{@code RESPONSE_SENT} – response has been written to the stream; waiting for FIN to clean up.</li>
         * </ul>
         */
        enum RequestProcessingState {
            INITIAL,
            WAITING_FOR_BODY,
            WAITING_FOR_FIN,
            RESPONSE_SENT
        }

        /**
         * A fully-buffered HTTP/3 frame (type + payload).
         *
         * @param type    HTTP/3 frame type varint value.
         * @param payload raw payload bytes.
         */
        record ParsedFrame(long type, byte[] payload) {
            ByteBuffer payloadAsBuffer() {
                return ByteBuffer.wrap(payload);
            }
        }

        private final long streamId;
        private final ByteBuffer dataBuffer = ByteBuffer.allocate(64 * 1024); // 64 KB buffer

        /** HTTP/3-level role of this stream (determined from the QUIC stream type or the stream-type varint). */
        private Http3StreamRole role;

        /** Read cursor: how many bytes from dataBuffer have already been consumed as complete frames. */
        private int readCursor = 0;

        // ---- request state machine ----
        private RequestProcessingState requestState = RequestProcessingState.INITIAL;
        private Http3Request request;

        public int readBodyBytes = 0;

        Http3StreamContext(long streamId, Http3StreamRole role) {
            this.streamId = streamId;
            this.role = role;
        }

        Http3StreamRole getRole() {
            return role;
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

        /**
         * Attempts to determine the HTTP/3 role of a unidirectional stream by reading the
         * leading stream-type varint from the buffered data (RFC 9114 §6.2).
         * Does nothing if the role is already known or if not enough bytes are available yet.
         */
        void tryDetermineRole() {
            if (role != Http3StreamRole.UNKNOWN) {
                return;
            }
            // Peek at the buffer without advancing the write position.
            ByteBuffer peek = dataBuffer.duplicate().flip();
            if (!peek.hasRemaining()) {
                return; // No bytes yet.
            }
            long streamTypeVarint = QuicVarint.read(peek);
            role = switch ((int) streamTypeVarint) {
                case 0x00 -> Http3StreamRole.CONTROL;
                case 0x01 -> Http3StreamRole.PUSH;
                case 0x02 -> Http3StreamRole.QPACK_ENCODER;
                case 0x03 -> Http3StreamRole.QPACK_DECODER;
                default   -> {
                    logger.warn("Unknown unidirectional stream type 0x{} on stream {}",
                            Long.toHexString(streamTypeVarint), streamId);
                    yield Http3StreamRole.UNKNOWN;
                }
            };
        }

        void appendData(byte[] data) {
            if (dataBuffer.remaining() < data.length) {
                throw new IllegalStateException("Stream buffer overflow");
            }
            dataBuffer.put(data);
        }

        /**
         * Tries to parse the next complete HTTP/3 frame from the buffer starting at
         * {@link #readCursor}. Returns {@code null} if there are not enough bytes yet.
         * Advances {@link #readCursor} past the consumed frame on success.
         */
        @Nullable
        ParsedFrame pollFrame() {
            // Create a view of the bytes written so far, starting from readCursor.
            ByteBuffer view = dataBuffer.duplicate().flip();
            view.position(readCursor);

            if (!view.hasRemaining()) {
                return null;
            }

            // Mark the start so we can reset if we don't have a full frame.
            view.mark();

            // Need at least 1 byte for the type varint.
            if (view.remaining() < 1) {
                return null;
            }
            long frameType = QuicVarint.read(view);

            if (!view.hasRemaining()) {
                return null; // Not enough bytes for the length varint.
            }
            long frameLength = QuicVarint.read(view);

            if (view.remaining() < (int) frameLength) {
                return null; // Payload not fully arrived yet.
            }

            byte[] payload = new byte[(int) frameLength];
            view.get(payload);

            readCursor = view.position();
            return new ParsedFrame(frameType, payload);
        }

        /**
         * Returns {@code true} if there are bytes in the buffer that have not yet been
         * consumed by {@link #pollFrame()} — i.e. the buffer holds a partial (truncated) frame.
         * Per RFC 9114 §4.1, a FIN while unconsumed bytes remain MUST be a connection error.
         */
        boolean hasUnconsumedData() {
            return readCursor < dataBuffer.position();
        }

        ByteBuffer getData() {
            return dataBuffer.duplicate().flip();
        }

        int getDataLength() {
            return dataBuffer.position();
        }
    }
}
