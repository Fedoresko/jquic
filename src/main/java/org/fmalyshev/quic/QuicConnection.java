package org.fmalyshev.quic;

import ch.qos.logback.core.pattern.color.ANSIConstants;
import org.fmalyshev.LogTool;
import org.fmalyshev.quic.streamapi.StreamFrameListener;
import org.fmalyshev.quic.streamapi.impl.QuicStreamEngineImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.SocketAddress;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.*;
import java.util.function.Consumer;

import static org.fmalyshev.quic.QuicCrypto.GCM_TAG_LENGTH;
import static org.fmalyshev.quic.QuicCrypto.rotateApplicationKeys;
import static org.fmalyshev.quic.streamapi.impl.StreamFrameProcessor.*;

/**
 * Represents a QUIC connection with its cryptographic state and metadata.
 */
public class QuicConnection implements TimeoutHeap.Entry {
    private static final Logger logger = LoggerFactory.getLogger(QuicConnection.class);
    private static final LogTool log = new LogTool(logger);
    public static final int ERR_PROTOCOL_VIOLATION = 10;
    public static final int ERR_TLS_HANDSHAKE_FAILURE = 0x0100 + 40;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int STATELESS_RESET_TOKEN_LENGTH = 16; // RFC 9000: 16 bytes
    private static final int MIN_STATELESS_RESET_LENGTH = 21; // 1 byte fixed bit + 4 bytes unpredictable + 16 bytes token

    /**
     * QUIC connection state following the connection lifecycle.
     */
    public enum State {
        INITIAL,           // Waiting for Initial packet
        HANDSHAKE,         // TLS handshake in progress
        ESTABLISHED,       // Handshake complete, 1-RTT keys active
        CLOSING,           // Connection closing
        CLOSED             // Connection closed
    }

    // RFC 9000 Section 10.1: Idle Timeout
    private static final long DEFAULT_IDLE_TIMEOUT_MS = 30_000; // 30 seconds
    private static final long MAX_IDLE_TIMEOUT_MS = 600_000; // 10 minutes

    private final long connectionId;
    private final SocketAddress remoteAddress;
    private State state;
    private QuicCrypto.TlsMetadata tlsMetadata = new QuicCrypto.TlsMetadata();
    private final long creationTime;
    private int timeoutHeapIndex = -1;

    // ALPN - negotiated application protocol (RFC 9001 Section 8.1)
    private String negotiatedProtocol = null;

    // Timeout tracking (RFC 9000 Section 10.1)
    private long idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS;
    private volatile long timeoutTimestamp;

    // Packet number spaces (RFC 9000 Section 12.3)
    private final PacketNumberSpace initialSpace = new PacketNumberSpace("Initial");
    private final PacketNumberSpace handshakeSpace = new PacketNumberSpace("Handshake");
    private final PacketNumberSpace applicationSpace = new PacketNumberSpace("Application");

    // Stream frame delivery
    private StreamFrameCallbackListener streamFrameCallbackListener = null;
    private StreamFrameListener streamFrameListener = null;

    /** Maximum number of early 1-RTT packets buffered before ESTABLISHED. */
    private static final int MAX_EARLY_1RTT_QUEUE = 32;

    /**
     * Early 1-RTT packets that arrived before the connection reached ESTABLISHED.
     * Drained automatically when the state transitions to ESTABLISHED.
     */
    private final Deque<ByteBuffer> earlyOneRttQueue = new ArrayDeque<>();

    /**
     * Outbound packet queue: completed, encrypted QUIC packets ready to send.
     * Produced by {@code QuicConnection} (early-1RTT drain, {@link #send1RttPacket}),
     * consumed by the owning {@code SelectorThread} which polls it and pushes
     * packets to the {@code DatagramChannel}.
     * SPSC: single producer (this connection, always on the selector thread),
     * single consumer (the selector thread).
     */
    private final Deque<ByteBuffer> outboundQueue = new ArrayDeque<>();

    private CryptoFrameRebuilder cryptoFrameRebuilder;
    private byte[] clientCid;

    /**
     * Sends a frame immediately over the connection.
     * Wraps the frame in a 1-RTT packet, encrypts it, updates PacketNumberSpace, and sends to socket.
     *
     * @param frame The frame to send (already encoded)
     * @throws Exception if sending fails
     */
    public void send1RttPacket(ByteBuffer frame) throws Exception {
        if (state != State.ESTABLISHED) {
            logger.warn("Cannot send frame, connection not established (state: {})", state);
            return;
        }

        sendApplicationPacket(frame);
    }

    public void setStreamFrameListener(StreamFrameListener listener) {
        this.streamFrameListener = listener;
        this.streamFrameCallbackListener = new StreamFrameCallbackListener(listener, connectionId);
    }

    /**
     * Polls one outbound packet from the connection's outbound queue.
     * The owning {@code SelectorThread} calls this after every processing cycle
     * to drain any packets that were produced internally (early-1RTT replay,
     * {@link #send1RttPacket}, etc.) and send them to the {@code DatagramChannel}.
     *
     * @return the next ready-to-send encrypted packet, or {@code null} if the queue is empty
     */
    public ByteBuffer pollOutbound() {
        return outboundQueue.pollFirst();
    }

    public int outboundQueueSize() {
        return outboundQueue.size();
    }

    /**
     * Buffers a 1-RTT packet snapshot that arrived before the connection was
     * {@link State#ESTABLISHED}. The snapshot will be replayed via the registered
     * drain callback once the handshake completes.
     *
     * <p>Packets are silently dropped when the queue reaches {@value #MAX_EARLY_1RTT_QUEUE}
     * entries to prevent unbounded memory growth from misbehaving clients.
     *
     * @param snapshot a self-contained, flipped {@link ByteBuffer} copy of the packet
     */
    public void enqueueEarlyOneRtt(ByteBuffer snapshot) {
        if (earlyOneRttQueue.size() < MAX_EARLY_1RTT_QUEUE) {
            earlyOneRttQueue.addLast(snapshot);
            logger.debug("Queued early 1-RTT packet for CID: {} (queue depth: {})",
                    connectionId, earlyOneRttQueue.size());
        } else {
            logger.warn("Early 1-RTT queue full for CID: {}, dropping packet", connectionId);
        }
    }

    public QuicConnection(long connectionId, SocketAddress remoteAddress) {
        this.connectionId = connectionId;
        this.remoteAddress = remoteAddress;
        this.state = State.INITIAL;
        this.creationTime = System.currentTimeMillis();
        this.timeoutTimestamp = creationTime + idleTimeoutMs;
    }

    public void setTimeoutHeapIndex(int index) {
        this.timeoutHeapIndex = index;
    }

    public int getTimeoutHeapIndex() {
        return timeoutHeapIndex;
    }

    /**
     * Updates the timeout timestamp based on recent activity.
     * Called when packets are sent or received.
     * Thread-safe via volatile.
     */
    public void updateTimeout() {
        this.timeoutTimestamp = System.currentTimeMillis() + idleTimeoutMs;
        logger.info("Connection {} time out updated to {}", connectionId, timeoutTimestamp);
    }

    /**
     * Gets the timeout timestamp (milliseconds since epoch).
     * Connection should be closed if current time exceeds this value.
     *
     * @return Timeout timestamp in milliseconds
     */
    public long getTimeoutTimestamp() {
        return timeoutTimestamp;
    }

    /**
     * Sets the idle timeout duration.
     *
     * @param timeoutMs Timeout duration in milliseconds
     */
    public void setIdleTimeout(long timeoutMs) {
        this.idleTimeoutMs = Math.min(timeoutMs, MAX_IDLE_TIMEOUT_MS);
        updateTimeout();
    }

    public long getConnectionId() {
        return connectionId;
    }

    public SocketAddress getRemoteAddress() {
        return remoteAddress;
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        State previousState = this.state;
        this.state = state;

        logger.info("Connection {} in new state {} ", connectionId, state);

        // Register with stream engine when transitioning to ESTABLISHED
        if (state == State.ESTABLISHED && previousState != State.ESTABLISHED) {
            if (negotiatedProtocol != null) {
                QuicStreamEngineImpl engine =
                        QuicEngine.getStreamEngineInternal();
                if (engine != null) {
                    engine.createConnection(connectionId, this, negotiatedProtocol);
                    logger.info("Registered connection {} with stream engine (protocol: {})",
                            connectionId, negotiatedProtocol);
                } else {
                    logger.warn("Stream engine not available to register connection {}", connectionId);
                }
            } else {
                logger.warn("Cannot register connection {} - no negotiated protocol", connectionId);
            }

            // Drain early 1-RTT packets that arrived before the handshake completed.
            // Process each one and push any responses into the outbound queue so the
            // owning SelectorThread can pick them up without needing a callback.
            if (!earlyOneRttQueue.isEmpty()) {
                logger.info("Draining {} early 1-RTT packet(s) for CID: {}",
                        earlyOneRttQueue.size(), connectionId);
                ByteBuffer snapshot;
                while ((snapshot = earlyOneRttQueue.pollFirst()) != null) {
                    try {
                        process1RttPacket(snapshot);
                    } catch (Exception ex) {
                        logger.error("Failed to replay early 1-RTT packet for CID: {}", connectionId, ex);
                    }
                }
            }
        }

        // Unregister when transitioning to CLOSING or CLOSED
        if ((state == State.CLOSING || state == State.CLOSED) &&
                (previousState != State.CLOSING && previousState != State.CLOSED)) {
            if (state == State.CLOSING) {
                PacketNumberSpace space = switch (previousState) {
                    case INITIAL -> initialSpace;
                    case HANDSHAKE -> handshakeSpace;
                    case ESTABLISHED -> applicationSpace;
                    default -> null;
                };
                this.timeoutTimestamp = System.currentTimeMillis() + 3 * space.getPTO();
            }

            QuicStreamEngineImpl engine =
                    QuicEngine.getStreamEngineInternal();
            if (engine != null) {
                engine.removeConnection(connectionId, null, null);
                logger.info("Unregistered connection {} from stream engine", connectionId);
            }
        }
    }

    public QuicCrypto.TlsMetadata getTlsMetadata() {
        return tlsMetadata;
    }

    public void setTlsMetadata(QuicCrypto.TlsMetadata tlsMetadata) {
        this.tlsMetadata = tlsMetadata;

        // Apply negotiated idle timeout from TLS handshake
        if (tlsMetadata.negotiatedIdleTimeoutMs > 0) {
            setIdleTimeout(tlsMetadata.negotiatedIdleTimeoutMs);
            logger.info("Applied negotiated idle timeout: {} ms for CID: {}",
                    tlsMetadata.negotiatedIdleTimeoutMs, connectionId);
        }
    }

    public PacketNumberSpace getInitialSpace() {
        return initialSpace;
    }

    public PacketNumberSpace getHandshakeSpace() {
        return handshakeSpace;
    }

    public PacketNumberSpace getApplicationSpace() {
        return applicationSpace;
    }

    private ByteBuffer processInitialPacket(ByteBuffer packet) {
        // RFC 9001 Section 5.2: Initial keys are derived deterministically from the DCID.
        // They carry no per-connection secret, so there is no need to store them as fields.
        int packetLen = packet.remaining();
        ByteBuffer tt = packet.duplicate();
        tt.get(); //flags
        tt.getInt();  //version

        // Read DCID
        int dcidLen = tt.get() & 0xFF;
        byte[] destinationCid = new byte[dcidLen];
        tt.get(destinationCid);

        boolean isNewConnection = false;
        if (tlsMetadata.clientInitialKeys == null) {
            tlsMetadata.originalDCid = destinationCid;
            isNewConnection = true;
            try {
                QuicCrypto.PacketProtectionKeys[] keys = QuicCrypto.deriveInitialKeys(
                        destinationCid);
                tlsMetadata.clientInitialKeys = keys[0];
                tlsMetadata.serverInitialKeys = keys[1];
            } catch (QuicCrypto.CryptoException e) {
                // RFC 9000: Silently discard packets that fail key derivation
                logger.warn("Failed to derive Initial keys for CID: {}, discarding packet", connectionId);
                return null;
            }
        }

        // Parse masked header (packet number still protected)
        QuicPacketHeader header = QuicPacketHeader.parse(packet, tlsMetadata.clientInitialKeys.headerProtection);
        if (header == null) {
            // RFC 9000: Silently discard malformed packets
            logger.warn("Failed to parse Initial packet header for CID: {}, discarding", connectionId);
            return null;
        }

        this.clientCid = header.sourceCid;

        // Decrypt payload and verify GCM authentication tag
        // RFC 9001 Section 5.3: AEAD provides both confidentiality and authentication
        if (header.payloadLength < 0) {
            // RFC 9000: Silently discard packets with invalid payload length
            logger.warn("Invalid Initial packet payload length for CID: {}, discarding", connectionId);
            return null;
        }

        initialSpace.onPacketReceived(header.packetNumber);

        try {
            return decryptAeadInPlace(packet, header, (int) header.payloadLength - header.pnLength, tlsMetadata.clientInitialKeys);
        } catch (Exception e) {
            // RFC 9000: Silently discard packets that fail decryption or tag verification
            logger.warn("Initial packet decryption/authentication failed for CID: {}, issue stateless reset",
                    connectionId, e);
            if (isNewConnection) {
                sendStatelessReset(packetLen);
            } else {
                sendConnectionClosePacket(ERR_PROTOCOL_VIOLATION);
            }
            return null;
        }
    }

    private ByteBuffer decryptAeadInPlace(ByteBuffer packet, QuicPacketHeader header, int length, QuicCrypto.PacketProtectionKeys keys) throws GeneralSecurityException {
        ByteBuffer plaintext;
        int startLimit = packet.limit();
        int startPos = packet.position();
        packet.limit(packet.position() + length);

        plaintext = packet.duplicate();
        // RFC 9001 Section 5.3: decryptAead verifies the GCM tag
        try {
            QuicCrypto.decryptAead(packet, keys.key, keys.iv,
                    header.packetNumber, plaintext, header.rawData);
//            logger.debug("Decrypted Initial packet, packet number: {}, GCM tag verified", header.packetNumber);
        } finally {
            packet.limit(startLimit);
        }

        plaintext.limit(plaintext.position());
        plaintext.position(startPos);
        return plaintext;
    }

    /**
     * Processes client's Handshake packet and generates server's Handshake response.
     * This completes the QUIC handshake (RFC 9000 Section 7).
     * The packet buffer position is advanced as data is read.
     *
     * @return List containing Handshake response (Certificate/Finished) and HANDSHAKE_DONE packets,
     * or empty list if connection not in HANDSHAKE state or packet is malformed
     */
    public void processHandshakePacket(ByteBuffer packet) {
        logger.debug("Processing Handshake packet for CID: {} in state: {}", connectionId, state);

        // RFC 9000: Handshake packets are only valid in HANDSHAKE state
        if (state != State.HANDSHAKE) {
            logger.warn("Received Handshake packet for CID: {} in invalid state: {}, discarding",
                    connectionId, state);
            SelectorThread.skipPacket(packet);
            return;
        }

        if (tlsMetadata == null) {
            // RFC 9000: Silently discard packets when TLS state is not ready
            logger.warn("No TLS metadata available for Handshake packet on CID: {}, discarding", connectionId);
            SelectorThread.skipPacket(packet);
            return;
        }

        // Parse and decrypt packet — use the HP key pre-derived in TlsMetadata
        // (RFC 9001 Section 5.4: Handshake level hp_key derived via "quic hp")
        QuicPacketHeader header = QuicPacketHeader.parse(packet, tlsMetadata.clientHandshakeKeys.headerProtection);
        if (header == null) {
            // RFC 9000: Silently discard malformed packets
            logger.warn("Failed to parse Handshake packet header for CID: {}, discarding", connectionId);
            SelectorThread.skipPacket(packet);
            return;
        }

        ByteBuffer frames;
        try {
            frames = decryptAeadInPlace(packet, header, (int) header.payloadLength - header.pnLength, tlsMetadata.clientHandshakeKeys);
        } catch (Exception e) {
            packet.position(packet.limit());
            logger.warn("Handshake packet decryption/authentication failed for CID: {}, discarding",
                    connectionId, e);
            return;
        }

        // Track received packet in Handshake space
        handshakeSpace.onPacketReceived(header.packetNumber);

        boolean needAck = false;

        while (frames.hasRemaining()) {
            byte frameType = frames.get();

            if (frameType == 0x02 || frameType == 0x03) { // ACK or ACK_ECN
                logger.info("Received Handshake ACK for CID: {}", connectionId);
                processAckFrame(frames, initialSpace, frameType); // ACK for Initial packets
                updateTimeout();
            } else if (frameType == 0x00) { // PADDING
                // Skip padding
            } else if (frameType == 0x01) { //PING
                needAck = true;
                updateTimeout();
                logger.info("Received Handshake PING for CID {} ", connectionId);
            } else if (frameType == 0x06) { // CRYPTO frame (contains client Finished)
                needAck = true;
                updateTimeout();



                    // RFC 9000 Section 19.6: CRYPTO frame format
                // type(0x06) | offset(varint) | length(varint) | data(*)
                long offset = QuicVarint.read(frames);
                long length = QuicVarint.read(frames);

                logger.info("Received Handshake CRYPTO frame for CID: {}, offset={}, length={}",
                        connectionId, offset, length);

                try {
                    rebuildCryptoFrame(offset, length, frames, this::extractCryptoFrame);
                } catch (IllegalStateException e) {
                    logger.warn("Failed to parse/verify client Finished for CID: {}, discarding packet: {}",
                            connectionId, e.getMessage());
                    // RFC 9000: Silently discard invalid packets - do NOT set receivedFinished
                    break;
                }
            } else if (frameType == 0x1c || frameType == 0x1d) {
                parseConnectionCloseFrame(frames, frameType);
            } else {
                logger.warn("Got unsupported handshake frame type: 0x{}, closing connection", String.format("%02x", frameType));
                sendConnectionCloseAndUpdateState();
                break;
            }
        }

        if (needAck) {
           sendHandshakeAck();
        }
    }

    private void extractCryptoFrame(ByteBuffer clientFinishedBytes) {
        // Extract crypto data
        if (state == State.HANDSHAKE) {
            logger.info("Received complete client Handshake, verifying client Finished.");

            try {
                boolean verified = QuicCrypto.verifyClientFinished(
                        clientFinishedBytes,
                        tlsMetadata.clientHandshakeTrafficSecret,
                        tlsMetadata.transcriptHash()
                );

                if (!verified) {
                    logger.warn("Client Finished verification failed for CID: {}, discarding packet",
                            connectionId);
                    // RFC 9000: Silently discard invalid packets - do NOT set receivedFinished
                    return;
                }

                logger.info("Client Finished verified successfully for CID: {}", connectionId);

                // Now the transcript contains all server Handshake messages.
                // Append the client Finished and derive 1-RTT keys (RFC 8446 §7.1).
                // The correct order is: ClientHello → ServerHello → Certificate →
                // CertificateVerify → server Finished → client Finished.

                QuicCrypto.createApplicationKeys(tlsMetadata);
                logger.debug("1-RTT application keys derived (transcript complete)");

                tlsMetadata.updateTranscript(clientFinishedBytes);
                logger.debug("Transcript updated with client Finished ({} bytes)", clientFinishedBytes.remaining());

                // Generate HANDSHAKE_DONE packet (uses server1RttSecret, now available)
                sendHandshakeDonePacket();

                // Transition to ESTABLISHED state (this will trigger registration via setState)
                setState(State.ESTABLISHED);

                logger.info("Handshake COMPLETE for CID: {}, connection ESTABLISHED", connectionId);
            } catch (Exception e) {
                logger.error("Failed to create Handshake response", e);
            }
        } else {
            logger.warn("Not in HANDSHAKE state, ignoring ClientFinished.");
        }
    }

    /**
     * Processes 1-RTT (Short Header) packet: decrypts and parses frames.
     * The packet buffer position is advanced as data is read.
     * Stream data is delivered to the payload listener.
     *
     * @return List of packets to send (ACKs and retransmissions), or empty list
     */
    public void process1RttPacket(ByteBuffer packet) {
        logger.debug("Processing 1-RTT packet for CID: {} in state: {}", connectionId, state);

        // RFC 9000: 1-RTT packets are only valid in ESTABLISHED or CLOSING states
        if (state != State.ESTABLISHED && state != State.CLOSING) {
            logger.warn("Received 1-RTT packet for CID: {} in invalid state: {}, enqueueing for later processing",
                    connectionId, state);

            ByteBuffer snapshot = ByteBuffer.allocateDirect(packet.remaining());
            snapshot.put(packet);
            snapshot.flip();
            enqueueEarlyOneRtt(snapshot);

            packet.position(packet.limit());
            return;
        }

        // If in CLOSING state, only process CONNECTION_CLOSE frames (done below)
        if (state == State.CLOSING) {
            logger.debug("Processing 1-RTT packet in CLOSING state for CID: {}", connectionId);
            SelectorThread.skipPacket(packet);
            packet.position(packet.limit());

            return;
        }

        if (tlsMetadata == null || tlsMetadata.clientApplicationKeys.key == null) {
            // RFC 9000: Silently discard packets when 1-RTT keys are not available
            logger.warn("No 1-RTT keys available for CID: {}, discarding packet", connectionId);
            packet.position(packet.limit());
            return;
        }

        byte [] tt = new byte[packet.remaining()];
        packet.mark();
        packet.get(tt);
        packet.reset();
        logger.info("Row data: {}", HexFormat.of().formatHex(tt));

        // Parse short header — use the HP key pre-derived in TlsMetadata
        // (RFC 9001 Section 5.4: 1-RTT level hp_key derived via "quic hp")
        QuicPacketHeader header = QuicPacketHeader.parse(packet, tlsMetadata.clientApplicationKeys.headerProtection);
        logger.debug("Processing 1-RTT packet: CID={}, packetNumber={}, ", header.destinationCid, header.packetNumber);

        // Rotate secrets based on the Key Phase flag.
        byte phase = (byte) (header.flags & 0x04);
        if (phase != tlsMetadata.currentPhase) {
            try {
                rotateApplicationKeys(tlsMetadata);
            } catch (QuicCrypto.CryptoException e) {
                logger.error("Could not rotate secrets", e);
                packet.position(packet.limit());
                return;
            }
        }

        // Update idle timeout on activity
        updateTimeout();

        ByteBuffer plaintext;

        try {
            plaintext = decryptAeadInPlace(packet, header, packet.remaining(), tlsMetadata.clientApplicationKeys);
        } catch (Exception e) {
            logger.warn("1-RTT packet decryption/authentication failed for CID: {}, discarding: {}", connectionId, e.getMessage());
            packet.position(packet.limit());
            return;
        }

        // Track received packet in Application space
        applicationSpace.onPacketReceived(header.packetNumber);

        boolean needsAck = false;

        while (plaintext.hasRemaining()) {
            byte frameType = plaintext.get();

            if (frameType == 0x02 || frameType == 0x03) { // ACK or ACK_ECN
                logger.info("Received 1-RTT ACK for CID: {}", connectionId);
                processAckFrame(plaintext, applicationSpace, frameType);
            } else if (frameType == 0x1c || frameType == 0x1d) { // CONNECTION_CLOSE
                String closeType = frameType == 0x1c ? "QUIC" : "Application";
                logger.info("Received CONNECTION_CLOSE ({}) for CID: {}", closeType, connectionId);
                parseConnectionCloseFrame(plaintext, frameType);

                needsAck = true; // CONNECTION_CLOSE is ack-eliciting
                break; // CONNECTION_CLOSE terminates the packet
            } else if ((frameType & FRAME_TYPE_STREAM) != 0) { // Stream-related frames: STREAM (0x08-0x0f)
                logger.info("Got Stream frame CID {} frame type {}", connectionId, frameType);

                boolean hasOffset = (frameType & 0x04) != 0;
                boolean hasLength = (frameType & 0x02) != 0;
                boolean fin = (frameType & 0x01) != 0;

                long streamId = QuicVarint.read(plaintext);
                long offset = (hasOffset) ? QuicVarint.read(plaintext) : 0;
                long length = (hasLength) ? QuicVarint.read(plaintext) : plaintext.remaining();

                byte[] data = new byte[(int) Math.min(length, plaintext.remaining())];
                plaintext.get(data);
                log.info(ANSIConstants.RED_FG,"STREAM frame received. Stream id {}, data: {}, str: {}", streamId, HexFormat.of().formatHex(data), new String(data));

                if (streamFrameListener != null) {
                    streamFrameListener.onStreamFrame(connectionId, new StreamFrameData(streamId, offset, ByteBuffer.wrap(data), fin));
                } else {
                    logger.warn("No stream frame listener set, dropping frame type 0x{}", String.format("%02x", frameType));
                }
                needsAck = true; // All stream frames are ack-eliciting

            } else if (frameType == FRAME_TYPE_RESET_STREAM) { // RESET_STREAM
                long streamId  = QuicVarint.read(plaintext);
                long errorCode = QuicVarint.read(plaintext);
                long finalSize = QuicVarint.read(plaintext);
                logger.info("Received RESET_STREAM CID={} streamId={} errorCode={} finalSize={}",
                        connectionId, streamId, errorCode, finalSize);
                if (streamFrameListener != null) {
                    streamFrameListener.onStreamFrame(connectionId, new ResetStreamFrameData(streamId, errorCode, finalSize));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_STOP_SENDING) { // STOP_SENDING
                long streamId  = QuicVarint.read(plaintext);
                long errorCode = QuicVarint.read(plaintext);
                logger.info("Received STOP_SENDING CID={} streamId={} errorCode={}",
                        connectionId, streamId, errorCode);
                if (streamFrameListener != null) {
                    streamFrameListener.onStreamFrame(connectionId, new StopSendingFrameData(streamId, errorCode));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_MAX_STREAM_DATA) { //MAX_STREAM_DATA
                long streamId = QuicVarint.read(plaintext);
                long maxStramData = QuicVarint.read(plaintext);
                logger.info("Received MAX_STREAM_DATA {} {}", streamId, maxStramData);
                if (streamFrameListener != null) {
                    streamFrameListener.onStreamFrame(connectionId, new MaxStreamDataFrameData(streamId, maxStramData));
                }
            } else if (frameType == FRAME_TYPE_MAX_STREAMS_BIDI) { //MAX_STREAMS (Bidirectional)
                long maxStreams = QuicVarint.read(plaintext);
                logger.info("Received MAX_STREAMS (bidirectional) CID={} max={}", connectionId, maxStreams);
                if (streamFrameListener != null) {
                    streamFrameListener.onStreamFrame(connectionId, new MaxStreamsFrameData(maxStreams, true));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_MAX_STREAMS_UNI) { //MAX_STREAMS (Unidirectional)
                long maxStreams = QuicVarint.read(plaintext);
                logger.info("Received MAX_STREAMS (unidirectional) CID={} max={}", connectionId, maxStreams);
                if (streamFrameListener != null) {
                    streamFrameListener.onStreamFrame(connectionId, new MaxStreamsFrameData(maxStreams, false));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_STREAM_DATA_BLOCKED) { //STREAM_DATA_BLOCKED
                long streamId  = QuicVarint.read(plaintext);
                long dataLimit = QuicVarint.read(plaintext);
                logger.info("Received STREAM_DATA_BLOCKED CID={} streamId={} limit={}", connectionId, streamId, dataLimit);
                if (streamFrameListener != null) {
                    streamFrameListener.onStreamFrame(connectionId, new StreamDataBlockedFrameData(streamId, dataLimit));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_STREAMS_BLOCKED_BIDI) { //STREAMS_BLOCKED (Bidirectional)
                long streamLimit = QuicVarint.read(plaintext);
                logger.info("Received STREAMS_BLOCKED (bidirectional) CID={} limit={}", connectionId, streamLimit);
                if (streamFrameListener != null) {
                    streamFrameListener.onStreamFrame(connectionId, new StreamsBlockedFrameData(streamLimit, true));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_STREAMS_BLOCKED_UNI) { //STREAMS_BLOCKED (Unidirectional)
                long streamLimit = QuicVarint.read(plaintext);
                logger.info("Received STREAMS_BLOCKED (unidirectional) CID={} limit={}", connectionId, streamLimit);
                if (streamFrameListener != null) {
                    streamFrameListener.onStreamFrame(connectionId, new StreamsBlockedFrameData(streamLimit, false));
                }
                needsAck = true;
            } else if (frameType == 0x06) { // CRYPTO
                long cryptoOffset = QuicVarint.read(plaintext);
                long cryptoLength = QuicVarint.read(plaintext);
                int cryptoDataLen = (int) Math.min(cryptoLength, plaintext.remaining());
                plaintext.position(plaintext.position() + cryptoDataLen);
                logger.info("Received 1-RTT CRYPTO frame CID={} offset={} length={}",
                        connectionId, cryptoOffset, cryptoLength);
                needsAck = true;
            } else if (frameType == 0x07) { // NEW_TOKEN
                long tokenLength = QuicVarint.read(plaintext);
                int tokenDataLen = (int) Math.min(tokenLength, plaintext.remaining());
                plaintext.position(plaintext.position() + tokenDataLen);
                logger.info("Received NEW_TOKEN CID={} tokenLength={}", connectionId, tokenLength);
                needsAck = true;
            } else if (frameType == 0x10) { // MAX_DATA
                // RFC 9000 Section 19.9: maximum_data(varint)
                long maxData = QuicVarint.read(plaintext);
                logger.info("Received MAX_DATA CID={} maxData={}", connectionId, maxData);
                needsAck = true;
            } else if (frameType == FRAME_TYPE_DATA_BLOCKED) { // DATA_BLOCKED
                // RFC 9000 Section 19.12: maximum_data(varint)
                long dataLimit = QuicVarint.read(plaintext);
                logger.info("Received DATA_BLOCKED CID={} dataLimit={}", connectionId, dataLimit);
                needsAck = true;
            } else if (frameType == 0x18) { // NEW_CONNECTION_ID
                // RFC 9000 Section 19.15: sequence_number(varint) + retire_prior_to(varint) +
                //   length(1) + connection_id(*) + stateless_reset_token(16)
                long seqNum         = QuicVarint.read(plaintext);
                long retirePriorTo  = QuicVarint.read(plaintext);
                int cidLen          = plaintext.get() & 0xFF;
                plaintext.position(plaintext.position() + cidLen); // skip connection_id
                plaintext.position(plaintext.position() + 16);     // skip stateless_reset_token
                log.error(ANSIConstants.RED_FG,
                        "Connection migration initiated but NOT SUPPORTED! CID={} seqNum={} retirePriorTo={}",
                        connectionId, seqNum, retirePriorTo);
                needsAck = true;
            } else if (frameType == 0x19) { // RETIRE_CONNECTION_ID
                // RFC 9000 Section 19.16: sequence_number(varint)
                long seqNum = QuicVarint.read(plaintext);
                logger.info("Received RETIRE_CONNECTION_ID CID={} seqNum={}", connectionId, seqNum);
                needsAck = true;
            } else if (frameType == 0x1a) { // PATH_CHALLENGE
                // RFC 9000 Section 19.17: data(8 bytes)
                plaintext.position(plaintext.position() + 8);
                logger.info("Received PATH_CHALLENGE CID={}", connectionId);
                needsAck = true;
            } else if (frameType == 0x1b) { // PATH_RESPONSE
                // RFC 9000 Section 19.18: data(8 bytes)
                plaintext.position(plaintext.position() + 8);
                logger.info("Received PATH_RESPONSE CID={}", connectionId);
                needsAck = true;
            } else if (frameType == 0x1e) { // HANDSHAKE_DONE
                logger.debug("Received HANDSHAKE_DONE from client (unexpected)");
                needsAck = true;
            } else if (frameType == 0x30 || frameType == 0x31) { // DATAGRAM
                // RFC 9221: optional length(varint) + data(*)
                // 0x30 = no length field (consume rest of packet), 0x31 = length field present
                if (frameType == 0x31) {
                    long datagramLength = QuicVarint.read(plaintext);
                    int datagramDataLen = (int) Math.min(datagramLength, plaintext.remaining());
                    plaintext.position(plaintext.position() + datagramDataLen);
                    logger.info("Received DATAGRAM CID={} length={}", connectionId, datagramLength);
                } else {
                    int datagramDataLen = plaintext.remaining();
                    plaintext.position(plaintext.position() + datagramDataLen);
                    logger.info("Received DATAGRAM (no-length) CID={} length={}", connectionId, datagramDataLen);
                }
                needsAck = true;
            } else if (frameType == 0x00) { // PADDING
                // RFC 9000 Section 19.1: consume all consecutive PADDING bytes
                while (plaintext.hasRemaining() && plaintext.get(plaintext.position()) == 0x00) {
                    plaintext.get();
                }
            } else if (frameType == 0x01) { // PING
                logger.debug("Received PING for CID: {}", connectionId);
                updateTimeout();
                needsAck = true;
            } else {
                logger.debug("Unknown 1-RTT frame type: 0x{}", String.format("%02x", frameType));
                plaintext.position(plaintext.limit());
                break; // Cannot safely skip an unknown frame; stop parsing
            }
        }

        // Generate ACK packet if needed
        if (needsAck) {
            send1RttAck();
        }
    }

    /**
     * Processes client's Initial packet and generates server's Initial response.
     * This is the first step of the QUIC handshake (RFC 9000 Section 7).
     * <p>
     * Flow:
     * 1. Client sends: Initial (ClientHello)
     * 2. Server responds: Initial (ServerHello) ← this method
     * 3. Client sends: Handshake (Finished) ← handled by processHandshakePacket()
     * 4. Server responds: Handshake + 1-RTT (Certificate/Finished + HANDSHAKE_DONE)
     *
     * @param datagram The received datagram buffer containing Initial packet
     */
    public void processInitialAndRespond(ByteBuffer datagram) {
        if (state == State.CLOSING || state == State.CLOSED) {
            logger.warn("Connection is closing, no incoming packets processed");
            datagram.position(datagram.limit());
            return;
        }

        logger.debug("Processing Initial packet for CID: {} in state: {}", connectionId, state);

        // Step 1: Process Initial packet
        ByteBuffer frames = processInitialPacket(datagram);

        boolean needAck = false;

        while (frames != null && frames.hasRemaining()) {
            byte frameType = frames.get();

            if (frameType == 0x02 || frameType == 0x03) { // ACK or ACK_ECN
                logger.info("Received Initial ACK for CID: {}", connectionId);
                processAckFrame(frames, initialSpace, frameType); // ACK for Initial packets
            } else if (frameType == 0x00) { // PADDING
                // Skip padding
            } else if (frameType == 0x01) { // PING
                logger.info("Received Initial PING for CID: {}", connectionId);
                needAck = true;
                updateTimeout();
            } else if (frameType == 0x06) { // CRYPTO
                needAck = true;

                long offset = QuicVarint.read(frames);
                long length = QuicVarint.read(frames);

                logger.info("Received Initial CRYPTO frame for CID: {}, offset={}, length={}",
                        connectionId, offset, length);

                if(state != State.INITIAL) {
                    frames.position(Math.min(frames.limit(), frames.position() + (int) length));
                    logger.info("State is {}, skipping crypto frame.", state);
                } else {
                    try {
                        rebuildCryptoFrame(offset, length, frames, this::extractTlsMeta);
                    } catch (IllegalStateException e) {
                        logger.warn("Got inconsistent frame: {}", e.getMessage());
                    }
                }
            } else if (frameType == 0x1c || frameType == 0x1d) { // CONNECTION_CLOSE
                needAck = true;

                String closeType = frameType == 0x1c ? "QUIC" : "Application";
                logger.info("Received CONNECTION_CLOSE ({}) for CID: {}", closeType, connectionId);
                parseConnectionCloseFrame(frames, frameType);


                break;
            }
        }

        if (needAck) {
            sendInitialAck();
        }

        logger.debug("Initial packet processed for connection {}", connectionId);

        if (state == State.INITIAL && tlsMetadata.clientMetadata != null) {
            logger.info("Connection CID: {} got complete ClientHello, proceeding with handshake...", connectionId);
            // Step 3: Transition to HANDSHAKE state
            setState(State.HANDSHAKE);

            sendInitialResponse();

            try {
                QuicCrypto.generateHandshakeSecrets(tlsMetadata);

                // Generate Handshake response with server Certificate/Finished.
                // This updates the transcript with: Certificate, CertificateVerify, server Finished.
                sendHandshakePacket();
            } catch (Exception e) {
                logger.error("Failed to generate TLS Handshake packet", e);
            }
        } else {
            if (state != State.INITIAL) {
                logger.warn("Connection {}: already in state {}, initial packets not expected", connectionId, state);
            }
        }
    }

    private void rebuildCryptoFrame(long offset, long length, ByteBuffer frames, Consumer<ByteBuffer> readyFrameConsumer) {
        // Verify client Finished message (RFC 8446 Section 4.4.4)
        // RFC 9000: Invalid packets should be silently discarded, not cause exceptions
        if (cryptoFrameRebuilder == null) {
            cryptoFrameRebuilder = new CryptoFrameRebuilder();
            logger.info("Staring building CRYPTO frame for CID: {}", connectionId);
        }

        if (cryptoFrameRebuilder.addPart((int) offset, (int) length, frames)) {
            logger.info("Completed building CRYPTO frame for CID: {}, len {}",
                    connectionId, cryptoFrameRebuilder.getExpectedLength());

            ByteBuffer frame = cryptoFrameRebuilder.rebuild();
            cryptoFrameRebuilder = null;

            readyFrameConsumer.accept(frame);
        } else {
            if (offset < 4 && cryptoFrameRebuilder.getExpectedLength() == -1) {
                ByteBuffer partialHead = cryptoFrameRebuilder.peekEarlyHead(4);
                if (partialHead.remaining() == 4) {
                    int cryptoFrameLength = QuicCrypto.getCryptoFrameLength(partialHead);
                    logger.info("Expected CRYPTO frame length: {}", cryptoFrameLength);
                    cryptoFrameRebuilder.setExpectedLength(cryptoFrameLength);
                    if (cryptoFrameRebuilder.isComplete()) {
                        ByteBuffer frame = cryptoFrameRebuilder.rebuild();
                        cryptoFrameRebuilder = null;

                        readyFrameConsumer.accept(frame);
                    }
                }
            }
        }
    }

    private void extractTlsMeta(ByteBuffer frame) {
        try {
            QuicCrypto.TlsMetadata derivedMetadata = QuicCrypto.processClientHello(tlsMetadata, frame);

            // Extract ALPN from TLS metadata
            if (derivedMetadata.alpn != null) {
                this.negotiatedProtocol = derivedMetadata.alpn;
                logger.info("ALPN negotiated: {} for CID: {}", derivedMetadata.alpn, connectionId);
            } else {
                logger.warn("No ALPN negotiated for CID: {}", connectionId);
            }

            logger.debug("TLS keys derived, cipher: {}", derivedMetadata.selectedCipherSuite);
        }  catch (QuicCrypto.CryptoException e) {
            if (e.getDemandedGroupId() != null) {
                logger.warn("ClientHello does not contain Key for supported KPG algorithms. Requesting another one {}", e.getDemandedGroupId());

                tlsMetadata.clientMetadata = null;
                sendHelloRetryRequest(e.getDemandedGroupId());
                return;
            }

            // RFC 9000 Section 10.2.3: Send CONNECTION_CLOSE with CRYPTO_ERROR
            // Error code = 0x0100 + TLS alert value (using handshake_failure = 40)
            logger.error("Failed to process ClientHello for CID: {}, sending CONNECTION_CLOSE", connectionId, e);
            sendConnectionCloseAndUpdateState();
        }
    }

    private void sendConnectionCloseAndUpdateState() {
        try {
            setState(State.CLOSING);
            sendConnectionClosePacket(ERR_TLS_HANDSHAKE_FAILURE);
            logger.info("Sent CONNECTION_CLOSE for CID: {}, transitioning to CLOSING", connectionId);
        } catch (Exception encryptEx) {
            logger.error("Failed to encrypt CONNECTION_CLOSE packet", encryptEx);
            setState(State.CLOSED);
        }
    }

    private void sendConnectionClosePacket(long errorCode) {
        ByteBuffer closeFrame = QuicFrameBuilder.createConnectionCloseFrame(errorCode, "ClientHello processing failed");

        logger.debug("Sending CONNECTION_CLOSE Initial packet");
        sendInitialPacket(closeFrame);
    }

    private void sendHelloRetryRequest(short prefferedGroupId) {
        ByteBuffer payload = QuicCrypto.createHelloRetryRequest(prefferedGroupId);
        QuicCrypto.applyHelloRetryRequestToTranscript(tlsMetadata, payload);

        logger.debug("Sending HelloRetryRequest Initial packet");
        sendInitialPacket(payload);
    }

    private void sendPacket(ByteBuffer payload, PacketNumberSpace.PacketPhase phase) {
        PacketNumberSpace space = switch (phase) {
            case INITIAL -> initialSpace;
            case HANDSHAKE -> handshakeSpace;
            case APPLICATION -> applicationSpace;
        };

        long packetNumber = space.allocatePacketNumber();

        ByteBuffer completePacket;
        try {
            completePacket = switch (phase) {
                case INITIAL -> QuicPacketBuilder.buildInitialPacket(
                        clientCid,      // DCID = connection ID
                        connectionId,      // SCID = connection ID (server uses same)
                        packetNumber,
                        payload.duplicate(),            // Plaintext payload
                        tlsMetadata.serverInitialKeys
                    );
                case HANDSHAKE -> QuicPacketBuilder.buildHandshakePacket(
                        clientCid,      // DCID = connection ID
                        connectionId,      // SCID = connection ID (server uses same)
                        packetNumber,
                        payload.duplicate(),            // Plaintext payload
                        tlsMetadata.serverHandshakeKeys
                    );
                case APPLICATION ->  QuicPacketBuilder.build1RttPacket(
                        clientCid,
                        packetNumber,
                        payload.duplicate(),          // Plaintext payload
                        tlsMetadata.serverApplicationKeys,
                        tlsMetadata.currentPhase
                );
            };
        } catch (QuicCrypto.CryptoException e) {
            logger.error("Failed to build Initial packet", e);
            return;
        }

        logger.debug("Sending {} packet {}: {} bytes", phase, packetNumber, completePacket.remaining());

        // Track sent packet: store UNENCRYPTED payload for retransmission
        space.onPacketSent(packetNumber, payload, PacketNumberSpace.PacketPhase.INITIAL, true);

        outboundQueue.add(completePacket);
    }

    private void sendInitialPacket(ByteBuffer payload) {
        sendPacket(payload, PacketNumberSpace.PacketPhase.INITIAL);
    }
    private void sendHandshakePacket(ByteBuffer payload) {
        sendPacket(payload, PacketNumberSpace.PacketPhase.HANDSHAKE);
    }
    private void sendApplicationPacket(ByteBuffer payload) {
        sendPacket(payload, PacketNumberSpace.PacketPhase.APPLICATION);
    }

    /**
     * Creates Initial packet with ServerHello.
     */
    private void sendInitialResponse() {
        // Create ServerHello — uses the server's ephemeral public key already stored in tlsMetadata
        ByteBuffer serverHello = QuicCrypto.createServerHello(tlsMetadata);

        // Feed ServerHello into the running transcript hash
        byte[] serverHelloBytes = new byte[serverHello.remaining()];
        serverHello.duplicate().get(serverHelloBytes);
        tlsMetadata.updateTranscript(serverHelloBytes);
        logger.debug("Transcript updated with ServerHello ({} bytes)", serverHelloBytes.length);

        // Wrap in CRYPTO frame (this is the unencrypted payload)
        while (serverHello.hasRemaining()) {
            int oldLimit = serverHello.limit();
            if (serverHello.remaining() > tlsMetadata.clientMetadata.maxUdpPayloadSize - 17 - 16) {
                serverHello.limit(serverHello.position() + (int) tlsMetadata.clientMetadata.maxUdpPayloadSize - 17 - 16);
            }

            ByteBuffer cryptoFrame = QuicFrameBuilder.createCryptoFrame(0, serverHello);

            serverHello.limit(oldLimit);

            ByteBuffer payload = cryptoFrame;

            if (serverHello.remaining() == 0) {
                payload = merge(List.of(payload, QuicFrameBuilder.createAckFrame(initialSpace)));
                logger.debug("Sending ServerHello Initial packet");
            } else {
                logger.debug("Sending ServerHello + ACK Initial packet");
            }

            sendInitialPacket(payload);
        }
    }

    /**
     * Creates Handshake packet with EncryptedExtensions, Certificate, CertificateVerify, Finished.
     *
     * <p>TLS 1.3 server flight order (RFC 8446 §4.4):
     * EncryptedExtensions → Certificate → CertificateVerify → Finished
     * <p>
     * Each message is fed into the running transcript hash immediately after it is built,
     * so that CertificateVerify signs over EE+Cert and Finished covers the full flight.
     */
    public void sendHandshakePacket() throws Exception {
        // ── 1. EncryptedExtensions ────────────────────────────────────────────
        ByteBuffer encryptedExtensions = QuicCrypto.createEncryptedExtensions(tlsMetadata, connectionId);
        updateTranscript(encryptedExtensions, "EncryptedExtensions");

        // ── 2. Certificate ────────────────────────────────────────────────────
        ByteBuffer certificate = QuicCrypto.createCertificate();
        updateTranscript(certificate, "Certificate");

        // ── 3. CertificateVerify ──────────────────────────────────────────────
        // Transcript now covers EE + Cert; CertificateVerify signs over that hash.
        ByteBuffer certVerify = QuicCrypto.createCertificateVerify(tlsMetadata);
        updateTranscript(certVerify, "CertificateVerify");

        // ── 4. Finished ───────────────────────────────────────────────────────
        ByteBuffer finished = QuicCrypto.createServerFinished(tlsMetadata);
        updateTranscript(finished, "server Finished");

        // ── 5. Coalesce all four messages into a single CRYPTO frame payload ──
        ByteBuffer handshakeData = merge(List.of(encryptedExtensions, certificate, certVerify, finished));


        while (handshakeData.hasRemaining()) {
            int oldLimit = handshakeData.limit();
            ByteBuffer payload = QuicFrameBuilder.createCryptoFrame(handshakeData.position(),
                    handshakeData.limit(Math.min(oldLimit, handshakeData.position() + (int) tlsMetadata.clientMetadata.maxUdpPayloadSize - 16)));

            handshakeData.limit(oldLimit);

            logger.debug("Sending Handshake Crypto frame");
            sendHandshakePacket(payload);
        }
    }

    /**
     * Feeds a TLS handshake message into the running transcript hash and logs it.
     * The buffer's position is not advanced (uses a duplicate for reading).
     */
    private void updateTranscript(ByteBuffer message, String messageName) {
        byte[] bytes = new byte[message.remaining()];
        message.duplicate().get(bytes);
        tlsMetadata.updateTranscript(bytes);
        logger.debug("Transcript updated with {} ({} bytes)", messageName, bytes.length);
    }

    /**
     * Creates 1-RTT (Short Header) packet with HANDSHAKE_DONE frame.
     * This signals to the client that the handshake is complete.
     */
    private void sendHandshakeDonePacket() throws Exception {
        // Create HANDSHAKE_DONE frame (type 0x1e)
        ByteBuffer frame = QuicFrameBuilder.createHandshakeDoneFrame();

        logger.debug("Sending HANDSHAKE_DONE frame in 1-RTT packet");
        sendApplicationPacket(frame);
    }

    private void sendInitialAck() {
        ByteBuffer ackFrame = QuicFrameBuilder.createAckFrame(initialSpace);

        logger.debug("Sending ACK Initial packet");
        sendInitialPacket(ackFrame);
    }
    private void sendHandshakeAck() {
        ByteBuffer ackFrame = QuicFrameBuilder.createAckFrame(handshakeSpace);

        logger.debug("Sending Handshake ACK");
        sendHandshakePacket(ackFrame);
    }
    private void send1RttAck() {
        // Get ACK ranges from application space
        ByteBuffer ackFrame = QuicFrameBuilder.createAckFrame(applicationSpace);

        logger.debug("Sending 1-RTT ACK");
        sendApplicationPacket(ackFrame);
    }

    /**
     * Processes ACK frame and updates packet number space.
     * RFC 9000 Section 19.3: ACK Frame Format
     *
     * @return List of retransmission packets to send (re-wrapped with NEW packet numbers), or empty list
     */
    private void processAckFrame(ByteBuffer buffer, PacketNumberSpace space, byte frameType) {
        long largestAcked = QuicVarint.read(buffer);
        long ackDelay = QuicVarint.read(buffer);
        long rangeCount = QuicVarint.read(buffer);
        long firstRange = QuicVarint.read(buffer);

        if (rangeCount > 64) { //skip
            logger.error("Range count too high {}", rangeCount);
            for (int i = 0; i < rangeCount; i++) {
                if (!buffer.hasRemaining()) break;
                QuicVarint.read(buffer);
                QuicVarint.read(buffer);
            }
            if (frameType == 0x03) {
                long ect0 = QuicVarint.read(buffer); // 1. ECT(0) Packets
                long ect1 = QuicVarint.read(buffer); // 2. ECT(1) Packets
                long ce   = QuicVarint.read(buffer); // 3. Congestion Experienced Packets
            }
            return;
        }

        // Build ACK ranges
        List<PacketNumberSpace.AckRange> ackRanges = new ArrayList<>();

        // First range
        long smallest = largestAcked - firstRange;
        ackRanges.add(new PacketNumberSpace.AckRange(smallest, largestAcked));

        // Additional ranges
        long currentSmallest = smallest;
        for (int i = 0; i < rangeCount; i++) {
            long gap = QuicVarint.read(buffer) & 0x7FFF;
            long rangeLength = QuicVarint.read(buffer) & 0x7FFF;

            long rangeSmallest = currentSmallest - gap - 2;
            long rangeLargest = rangeSmallest + rangeLength;
            if (rangeSmallest < 0 || rangeSmallest >= rangeLargest || rangeLargest > 65535) {
                continue;
            }

            ackRanges.add(new PacketNumberSpace.AckRange(rangeSmallest, rangeLargest));

            currentSmallest = rangeSmallest;
        }

        if (frameType == 0x03) {
            long ect0 = QuicVarint.read(buffer); // 1. ECT(0) Packets
            long ect1 = QuicVarint.read(buffer); // 2. ECT(1) Packets
            long ce   = QuicVarint.read(buffer); // 3. Congestion Experienced Packets
        }

        space.onAckReceived(largestAcked, ackRanges, ackDelay, streamFrameCallbackListener);

        retransmitLostPackets(space);
    }

    private void retransmitLostPackets(PacketNumberSpace space) {
        Map<Long, PacketNumberSpace.SentPacket> lostPackets = space.detectLostPackets();

        // Re-wrap lost packets with NEW packet numbers and encryption
        if (!lostPackets.isEmpty()) {
            logger.warn("Detected {} lost packets, retransmitting with NEW packet numbers", lostPackets.size());

            for (Map.Entry<Long, PacketNumberSpace.SentPacket> entry : lostPackets.entrySet()) {
                long originalPn = entry.getKey();
                PacketNumberSpace.SentPacket sentPacket = entry.getValue();

                // Allocate a BRAND NEW packet number for retransmission
                logger.info("Retransmitting lost packet {} as new packet (phase: {})",
                        originalPn, sentPacket.packetPhase);

                sendPacket(sentPacket.unencryptedPayload, sentPacket.packetPhase);
            }
        }
    }

    /**
     * Parses CONNECTION_CLOSE frame (RFC 9000 Section 19.19).
     * Format: type(1) | error_code(varint) | [frame_type(varint)] | reason_length(varint) | reason(*)
     *
     * @param buffer    The buffer containing the frame data
     * @param frameType 0x1c for QUIC-level close, 0x1d for application-level close
     */
    private void parseConnectionCloseFrame(ByteBuffer buffer, byte frameType) {
        int packetSize = buffer.remaining();

        long errorCode = QuicVarint.read(buffer);

        // QUIC-level close (0x1c) includes frame type that triggered the error
        long triggeringFrameType = 0;
        if (frameType == 0x1c && buffer.hasRemaining()) {
            triggeringFrameType = QuicVarint.read(buffer);
        }

        // Read reason phrase
        long reasonLength = QuicVarint.read(buffer);
        String reason = "";
        if (reasonLength > 0 && buffer.remaining() >= reasonLength) {
            byte[] reasonBytes = new byte[(int) reasonLength];
            buffer.get(reasonBytes);
            reason = new String(reasonBytes, StandardCharsets.UTF_8);
        }

        if (tlsMetadata.clientHandshakeKeys == null) {
            sendStatelessReset(packetSize);
        }

        // RFC 9000: Transition to CLOSING if not already closing
        if (state != State.CLOSED && state != State.CLOSING) {
            setState(State.CLOSING);
        }

        if (frameType == 0x1c) {
            logger.info("CONNECTION_CLOSE (QUIC): error_code={}, frame_type={}, reason=\"{}\"",
                    errorCode, triggeringFrameType, reason);
        } else {
            logger.info("CONNECTION_CLOSE (Application): error_code={}, reason=\"{}\"",
                    errorCode, reason);
        }


    }

    /**
     * Sends a Stateless Reset packet as per RFC 9000 Section 10.3.
     * A Stateless Reset is indistinguishable from a regular packet with a short header,
     * containing random bytes and a 16-byte Stateless Reset Token at the end.
     *
     * @param incomingPacketSize Size of the incoming packet (used to determine reset size)
     */
    private void sendStatelessReset(int incomingPacketSize) {
        try {
            // RFC 9000: Stateless Reset should be smaller than incoming packet
            // to avoid amplification attacks, but at least 21 bytes
            int resetSize = Math.max(MIN_STATELESS_RESET_LENGTH,
                    Math.min(incomingPacketSize - 1, 1200));

            ByteBuffer resetPacket = ByteBuffer.allocate(resetSize);

            // First byte must have fixed bit (0x40) set to appear as valid short header
            byte firstByte = (byte) (0x40 | (SECURE_RANDOM.nextInt() & 0x3F));
            resetPacket.put(firstByte);

            // Fill with random unpredictable bits (excluding last 16 bytes for token)
            int randomBytesCount = resetSize - 1 - STATELESS_RESET_TOKEN_LENGTH;
            byte[] randomBytes = new byte[randomBytesCount];
            SECURE_RANDOM.nextBytes(randomBytes);
            resetPacket.put(randomBytes);

            // Add 16-byte Stateless Reset Token at the end
            // In a real implementation, this should be a pseudorandom function of the CID
            // For now, we use random bytes (stateless - doesn't require storing state)
            byte[] token = new byte[STATELESS_RESET_TOKEN_LENGTH];
            SECURE_RANDOM.nextBytes(token);
            resetPacket.put(token);

            resetPacket.flip();

            outboundQueue.push(resetPacket);
            logger.info("Sent Stateless Reset ({} bytes)", resetSize);

        } catch (Exception e) {
            logger.error("Failed to send Stateless Reset", e);
        }
    }

    private static ByteBuffer merge(List<ByteBuffer> buffers) {
        int combinedSize = buffers.stream().mapToInt(Buffer::remaining).sum();
        ByteBuffer merged = ByteBuffer.allocate(combinedSize);
        buffers.forEach(merged::put);
        return merged.flip();
    }
}
