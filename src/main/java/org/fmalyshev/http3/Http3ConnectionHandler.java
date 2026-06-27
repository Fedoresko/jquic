package org.fmalyshev.http3;

import org.fmalyshev.quic.QuicVarint;
import org.fmalyshev.quic.streamapi.QuicApplicationProtocolConnectionHandler;
import org.fmalyshev.quic.streamapi.QuicStreamResponse;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tech.kwik.qpack.Decoder;
import tech.kwik.qpack.Encoder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
    private final boolean useQpack;
    private final Encoder qpackEncoder = Encoder.newBuilder().build();
    private final Decoder qpackDecoder = Decoder.newBuilder().build();


    Http3ConnectionHandler(long connectionId, Http3RequestHandler requestHandler) {
        this(connectionId, requestHandler, true);
    }

    Http3ConnectionHandler(long connectionId, Http3RequestHandler requestHandler, boolean useQpack) {
        this.connectionId = connectionId;
        this.requestHandler = requestHandler;
        this.useQpack = useQpack;
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

        Http3StreamContext context = new Http3StreamContext(streamId, response, streamType, initialRole);
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
                // Client-initiated bidirectional request stream — process as HTTP/3 request.
                if (isLastData) {
                    logger.debug("Received complete HTTP/3 request on stream {} (connection {}): {} bytes",
                            streamId, connectionId, context.getDataLength());
                    try {
                        processHttpRequest(streamId, context, response);
                    } catch (Exception e) {
                        logger.error("Failed to process HTTP/3 request on stream " + streamId, e);
                        try {
                            response.closeStream(streamId, 0x0100); // H3_GENERAL_PROTOCOL_ERROR
                        } catch (Exception closeEx) {
                            logger.error("Failed to close stream after error", closeEx);
                        }
                    } finally {
                        streams.remove(streamId);
                    }
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
     * Processes a complete HTTP/3 request and sends response.
     */
    private void processHttpRequest(long streamId, Http3StreamContext context, QuicStreamResponse response) {
        // Parse HTTP/3 request (simplified - in real implementation would use QPACK)
        Http3Request request = parseRequest(context.getData());
        // Handle request using user-provided handler
        Http3Response httpResponse = requestHandler.handleRequest(request);

        // Send response
        try {
            response.sendData(streamId, buffer -> putResponse(buffer, httpResponse), true);
        } catch (Exception e) {
            logger.error("Failed to send HTTP/3 response on stream " + streamId, e);
        }
    }

    /**
     * Parses HTTP/3 request from raw bytes.
     * Uses QPACK decoding when {@code useQpack} is enabled,
     * otherwise falls back to the simplified plain-text format.
     */
    private Http3Request parseRequest(ByteBuffer data) {
        Http3Request req = new Http3Request(connectionId, null, null);
        while (data.hasRemaining()) {
            long frameType = QuicVarint.read(data);
            long frameLength = QuicVarint.read(data);
            int oldLim = data.limit();

            data.limit(data.position() + (int) frameLength);
            if (frameType == 1) {
                req = parseRequestQpack(data);
            } else {
                // Simplified: assume plain text format "METHOD PATH\r\n"
                String requestLine = new String(data.array(), data.position(), data.remaining(), StandardCharsets.UTF_8);
                req.data += requestLine;
            }
            data.limit(oldLim);
        }
        return req;
    }

    /**
     * Parses an HTTP/3 request that uses QPACK-encoded headers (RFC 9204).
     *
     * <p>The incoming {@code data} is expected to be the payload of an HTTP/3
     * HEADERS frame (frame type 0x01), i.e. a QPACK header block.
     */
    private Http3Request parseRequestQpack(ByteBuffer data) {
        if (useQpack) {
            try {
                Map<String, String> headers = qpackDecoder.decodeStream(new ByteArrayInputStream(data.array(), data.position(), data.remaining())).stream()
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

                String method = headers.getOrDefault(":method", "GET");
                String path = headers.getOrDefault(":path", "/");
                data.position(data.limit());
                return new Http3Request(connectionId, method, path);
            } catch (IOException e) {
                logger.warn("QPACK decoding failed on stream (connection {})",
                        connectionId, e.getMessage());
                return null;
            }
        } else {
            String requestLine = new String(data.array(), data.position(), data.remaining(), StandardCharsets.UTF_8).split("\r\n")[0];
            String[] parts = requestLine.split(" ");
            String method = parts.length > 0 ? parts[0] : "GET";
            String path = parts.length > 1 ? parts[1] : "/";
            data.position(data.limit());
            return new Http3Request(connectionId, method, path);
        }
    }


//    static class Entry implements Map.Entry<String, String> {
//        private Entry(String key, String value) {
//            this.key = key;
//            this.value = value;
//        }
//
//        public static Entry of(String key, String value) {
//            return new Entry(key, value);
//        }
//
//        private final String key;
//        private final String value;
//
//        @Override
//        public String getKey() {
//            return key;
//        }
//
//        @Override
//        public String getValue() {
//            return value;
//        }
//
//        @Override
//        public String setValue(String value) {
//            return "";
//        }
//
//        @Override
//        public boolean equals(Object o) {
//            return false;
//        }
//
//        @Override
//        public int hashCode() {
//            return 0;
//        }
//    }

    /**
     * Encodes HTTP/3 response to raw bytes.
     * Uses QPACK header compression when {@code useQpack} is enabled,
     * otherwise falls back to the simplified plain-text format.
     */
    private ByteBuffer putResponse(ByteBuffer buffer, Http3Response response) {
        byte[] body        = response.getBody();

        List<Map.Entry<String, String>> headers = new ArrayList<>(List.of(
                new AbstractMap.SimpleEntry<>(":status", String.valueOf(response.getStatusCode())),
                new AbstractMap.SimpleEntry<>("content-type", response.getContentType()),
                new AbstractMap.SimpleEntry<>("content-length", String.valueOf(body.length))));

        headers.addAll(response.getHeaders());

        ByteBuffer headerBlock = qpackEncoder.compressHeaders(headers).position(0);

        // HTTP/3 framing: each frame = type (varint) + length (varint) + payload
        putHttp3Frame(buffer,0x01, headerBlock);
        putHttp3Frame(buffer,0x00, body);

        return buffer.flip();
    }

    /**
     * Builds a minimal HTTP/3 frame with the given type and payload.
     * Uses single-byte varints (sufficient for payloads up to 63 bytes in type/length).
     */
    private void putHttp3Frame(ByteBuffer buf, int frameType, byte[] payload) {
        // Encode type and length as QUIC-style varints (1-byte form for values < 64)
        QuicVarint.write(buf, frameType);
        QuicVarint.write(buf, payload.length);
        buf.put(payload);
    }

    private void putHttp3Frame(ByteBuffer buf, int frameType, ByteBuffer payload) {
        // Encode type and length as QUIC-style varints (1-byte form for values < 64)
        QuicVarint.write(buf, frameType);
        QuicVarint.write(buf, payload.remaining());
        buf.put(payload);
    }

    /**
     * Context for a single HTTP/3 stream.
     */
    private static class Http3StreamContext {
        private final long streamId;
        private final QuicStreamResponse response;
        private final QuicStreamResponse.StreamType streamType;
        private final ByteBuffer dataBuffer = ByteBuffer.allocate(64 * 1024); // 64 KB buffer

        /** HTTP/3-level role of this stream (determined from the QUIC stream type or the stream-type varint). */
        private Http3StreamRole role;

        Http3StreamContext(long streamId, QuicStreamResponse response,
                           QuicStreamResponse.StreamType streamType, Http3StreamRole role) {
            this.streamId = streamId;
            this.response = response;
            this.streamType = streamType;
            this.role = role;
        }

        Http3StreamRole getRole() {
            return role;
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

        ByteBuffer getData() {
            return dataBuffer.duplicate().flip();
        }

        int getDataLength() {
            return dataBuffer.position();
        }
    }
}
