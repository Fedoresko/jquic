package org.fmalyshev.quic;

import ch.qos.logback.core.pattern.color.ANSIConstants;
import org.fmalyshev.LogTool;
import org.fmalyshev.quic.buffers.PoolBuffer;
import org.fmalyshev.quic.buffers.ChunkedOutputStreamWithAmendmentsImpl;
import org.fmalyshev.quic.buffers.RootPoolBuffer;
import org.fmalyshev.quic.buffers.TranscryptHashSupport;
import org.fmalyshev.quic.streamapi.ConnectionStreamManager;
import org.fmalyshev.quic.streamapi.frames.*;
import org.fmalyshev.quic.streamapi.impl.QuicStreamEngineImpl;
import org.jctools.queues.MessagePassingQueue;
import org.jctools.queues.SpscArrayQueue;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.fmalyshev.quic.QuicCrypto.GCM_TAG_LENGTH;
import static org.fmalyshev.quic.QuicCrypto.rotateApplicationKeys;
import static org.fmalyshev.quic.QuicFrameBuilder.*;
import static org.fmalyshev.quic.streamapi.impl.StreamFrameProcessor.*;

/**
 * Represents a QUIC connection with its cryptographic state and metadata.
 */
public class QuicConnection implements TimeoutHeap.Entry {
    private static final Logger logger = LoggerFactory.getLogger(QuicConnection.class);
    private static final LogTool log = new LogTool(logger);
    public static final int ERR_PROTOCOL_VIOLATION = 10;
    public static final int ERR_TLS_HANDSHAKE_FAILURE = 0x0100 + 40;
    public static final int OUTBOUND_APP_QUEUE_SIZE = 1000;

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
    private final ByteBuffer connectionIdBytes;
    private final SocketAddress remoteAddress;
    private final AtomicReference<State> state = new AtomicReference<>(State.INITIAL);
    public QuicCrypto.TlsMetadata tlsMetadata = new QuicCrypto.TlsMetadata();
    private final long creationTime;
    private int timeoutHeapIndex = -1;
    ConnectionStreamManager connectionStreamManager;

    // ALPN - negotiated application protocol (RFC 9001 Section 8.1)
    private String negotiatedProtocol = null;

    // Timeout tracking (RFC 9000 Section 10.1)
    private long idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS;
    private volatile long timeoutTimestamp;

    // Packet number spaces (RFC 9000 Section 12.3)
    private final PacketNumberSpace initialSpace = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);
    private final PacketNumberSpace handshakeSpace = new PacketNumberSpace(PacketNumberSpace.PacketPhase.HANDSHAKE);
    private final PacketNumberSpace applicationSpace = new PacketNumberSpace(PacketNumberSpace.PacketPhase.APPLICATION);

    /** Maximum number of early 1-RTT packets buffered before ESTABLISHED. */
    private static final int MAX_EARLY_1RTT_QUEUE = 32;

    /**
     * Early 1-RTT packets that arrived before the connection reached ESTABLISHED.
     * Drained automatically when the state transitions to ESTABLISHED.
     */
    private final Deque<PoolBuffer> earlyOneRttQueue = new ArrayDeque<>();

    /**
     * Outbound packet queue: completed, encrypted QUIC packets ready to send.
     * Produced by {@code QuicConnection} (early-1RTT drain, {@link #send1RttPacket}),
     * consumed by the owning {@code SelectorThread} which polls it and pushes
     * packets to the {@code DatagramChannel}.
     * SPSC: single producer (this connection, always on the selector thread),
     * single consumer (the selector thread).
     */
    private final Deque<PoolBuffer> outboundQueue = new ArrayDeque<>();

    private final MessagePassingQueue<ByteBuffer> applicationQueue = new SpscArrayQueue<>(OUTBOUND_APP_QUEUE_SIZE);

    private CryptoFrameRebuilder cryptoFrameRebuilder;
    byte[] clientCid;


    public void enqueueApplicationData(ByteBuffer applicationData) {
        applicationQueue.offer(applicationData);
    }

    MessagePassingQueue<ByteBuffer> applicationQueue() {
        return applicationQueue;
    }

    /**
     * Sends a frame immediately over the connection.
     * Wraps the frame in a 1-RTT packet, encrypts it, updates PacketNumberSpace, and sends to socket.
     *
     * @param frame The frame to send (already encoded)
     * @throws Exception if sending fails
     */
    void send1RttPacket(ByteBuffer frame) {
        if (state.get() != State.ESTABLISHED) {
            logger.warn("Cannot send frame, connection not established (state: {})", state);
            return;
        }

        sendApplicationPacket(frame);
    }

    /**
     * Polls one outbound packet from the connection's outbound queue.
     * The owning {@code SelectorThread} calls this after every processing cycle
     * to drain any packets that were produced internally (early-1RTT replay,
     * {@link #send1RttPacket}, etc.) and send them to the {@code DatagramChannel}.
     *
     * @return the next ready-to-send encrypted packet, or {@code null} if the queue is empty
     */
    PoolBuffer pollOutbound() {
        return outboundQueue.pollFirst();
    }

    int outboundQueueSize() {
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
    private void enqueueEarlyOneRtt(PoolBuffer snapshot) {
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
        this.connectionIdBytes = ByteBuffer.allocate(8).putLong(connectionId);
        this.remoteAddress = remoteAddress;
        this.state.set(State.INITIAL);
        this.creationTime = System.currentTimeMillis();
        this.timeoutTimestamp = creationTime + idleTimeoutMs;
        logger.info("Connection {} initial tiemout set to {}", connectionId, timeoutTimestamp);
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
    void updateTimeout() {
        this.timeoutTimestamp = System.currentTimeMillis() + idleTimeoutMs;
        logger.info("Connection {} tiemout updated to {}", connectionId, timeoutTimestamp);
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
    void setIdleTimeout(long timeoutMs) {
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
        return state.get();
    }

    void setState(State state) {
        State previousState = this.state.getAndSet(state);

        logger.info("Connection {} in new state {} ", connectionId, state);

        // Register with stream engine when transitioning to ESTABLISHED
        if (state == State.ESTABLISHED && previousState != State.ESTABLISHED) {
            if (negotiatedProtocol != null) {
                QuicStreamEngineImpl engine =
                        QuicEngine.getStreamEngineInternal();
                if (engine != null) {
                    connectionStreamManager = engine.createConnection(connectionId, this, negotiatedProtocol);
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
                PoolBuffer snapshot;
                while ((snapshot = earlyOneRttQueue.pollFirst()) != null) {
                    try {
                        process1RttPacket(snapshot);
                        snapshot.release();
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

    QuicCrypto.TlsMetadata getTlsMetadata() {
        return tlsMetadata;
    }

    void setTlsMetadata(QuicCrypto.TlsMetadata tlsMetadata) {
        this.tlsMetadata = tlsMetadata;

        // Apply negotiated idle timeout from TLS handshake
        if (tlsMetadata.negotiatedIdleTimeoutMs > 0) {
            setIdleTimeout(tlsMetadata.negotiatedIdleTimeoutMs);
            logger.info("Applied negotiated idle timeout: {} ms for CID: {}",
                    tlsMetadata.negotiatedIdleTimeoutMs, connectionId);
        }
    }

    PacketNumberSpace getInitialSpace() {
        return initialSpace;
    }

    PacketNumberSpace getHandshakeSpace() {
        return handshakeSpace;
    }

    PacketNumberSpace getApplicationSpace() {
        return applicationSpace;
    }

    private PoolBuffer processInitialPacket(PoolBuffer packet) {
        // RFC 9001 Section 5.2: Initial keys are derived deterministically from the DCID.
        // They carry no per-connection secret, so there is no need to store them as fields.
        int packetLen = packet.buf().remaining();
        ByteBuffer tt = packet.buf().duplicate();
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
                QuicCrypto.PacketProtectionKeysWithHP[] keys = QuicCrypto.deriveInitialKeys(
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
        QuicPacketHeader header = QuicPacketHeader.parse(packet.buf(), tlsMetadata.clientInitialKeys.headerProtection());
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
                sendConnectionCloseAndUpdateState(QuicTransportError.PROTOCOL_VIOLATION,
                "Initial packet crypto validation failed.");
            }
            return null;
        }
    }

    private PoolBuffer decryptAeadInPlace(PoolBuffer packet, QuicPacketHeader header, int length, QuicCrypto.PacketProtectionKeysWithHP keys) throws GeneralSecurityException {
        return decryptAeadInPlace(packet, header, length, keys.key(), keys.iv());
    }

    private PoolBuffer decryptAeadInPlace(PoolBuffer packet, QuicPacketHeader header, int length, QuicCrypto.PacketProtectionKeys keys) throws GeneralSecurityException {
        return decryptAeadInPlace(packet, header, length, keys.key(), keys.iv());
    }

    private PoolBuffer decryptAeadInPlace(PoolBuffer packet, QuicPacketHeader header, int length, SecretKey key, byte [] iv) throws GeneralSecurityException {
        PoolBuffer plaintext;
        int startLimit = packet.buf().limit();
        int startPos = packet.buf().position();
        packet.buf().limit(packet.buf().position() + length);

        plaintext = packet.borrow();
        // RFC 9001 Section 5.3: decryptAead verifies the GCM tag
        try {
            QuicCrypto.decryptAead(packet.buf(), key, iv,
                    header.packetNumber, plaintext.buf(), header.rawData);
//            logger.debug("Decrypted Initial packet, packet number: {}, GCM tag verified", header.packetNumber);
        } finally {
            packet.buf().limit(startLimit);
        }

        plaintext.buf().limit(plaintext.buf().position());
        plaintext.buf().position(startPos);
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
    void processHandshakePacket(PoolBuffer packet) {
        logger.debug("Processing Handshake packet for CID: {} in state: {}", connectionId, state);

        // RFC 9000: Handshake packets are only valid in HANDSHAKE state
        if (state.get() != State.HANDSHAKE) {
            logger.warn("Received Handshake packet for CID: {} in invalid state: {}, discarding",
                    connectionId, state);
            SelectorThread.skipPacket(packet.buf());
            return;
        }

        if (tlsMetadata == null) {
            // RFC 9000: Silently discard packets when TLS state is not ready
            logger.warn("No TLS metadata available for Handshake packet on CID: {}, discarding", connectionId);
            SelectorThread.skipPacket(packet.buf());
            return;
        }

        // Parse and decrypt packet — use the HP key pre-derived in TlsMetadata
        // (RFC 9001 Section 5.4: Handshake level hp_key derived via "quic hp")
        QuicPacketHeader header = QuicPacketHeader.parse(packet.buf(), tlsMetadata.clientHandshakeKeys.headerProtection());
        if (header == null) {
            // RFC 9000: Silently discard malformed packets
            logger.warn("Failed to parse Handshake packet header for CID: {}, discarding", connectionId);
            SelectorThread.skipPacket(packet.buf());
            return;
        }

        PoolBuffer frames;
        try {
            frames = decryptAeadInPlace(packet, header, (int) header.payloadLength - header.pnLength, tlsMetadata.clientHandshakeKeys);
        } catch (Exception e) {
            packet.buf().position(packet.buf().limit());
            logger.warn("Handshake packet decryption/authentication failed for CID: {}, discarding",
                    connectionId, e);
            return;
        }

        // Track received packet in Handshake space
        handshakeSpace.onPacketReceived(header.packetNumber);

        boolean needAck = false;

        while (frames.buf().hasRemaining()) {
            byte frameType = frames.buf().get();

            if (frameType == 0x02 || frameType == 0x03) { // ACK or ACK_ECN
                logger.info("Received Handshake ACK for CID: {}", connectionId);
                processAckFrame(frames.buf(), initialSpace, frameType); // ACK for Initial packets
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
                long offset = QuicVarint.read(frames.buf());
                long length = QuicVarint.read(frames.buf());

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
                parseConnectionCloseFrame(frames.buf(), frameType);
            } else {
                logger.warn("Got unsupported handshake frame type: 0x{}, closing connection", String.format("%02x", frameType));
                sendConnectionCloseAndUpdateState(ERR_TLS_HANDSHAKE_FAILURE, "Unsupported handshake frame type", false);
                break;
            }
        }

        frames.release();

        if (needAck && state.get() != State.CLOSING) {
           sendHandshakeAck();
        }
    }

    private void extractCryptoFrame(ByteBuffer clientFinishedBytes) {
        // Extract crypto data
        if (state.get() == State.HANDSHAKE) {
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
                    sendConnectionCloseAndUpdateState(QuicTransportError.TLS_ERROR_DECRYPT_ERROR, "Client Finished verification failed");
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
    void process1RttPacket(PoolBuffer packet) {
        logger.debug("Processing 1-RTT packet for CID: {} in state: {}", connectionId, state);

        // If in CLOSING state do nothing
        if (state.get() == State.CLOSING) {
            logger.debug("Processing 1-RTT packet in CLOSING state for CID: {}", connectionId);
            packet.buf().position(packet.buf().limit());
            return;
        }

        // RFC 9000: 1-RTT packets are only valid in the ESTABLISHED state
        if (state.get() != State.ESTABLISHED) {
            logger.warn("Received 1-RTT packet for CID: {} in invalid state: {}, enqueueing for later processing",
                    connectionId, state);

            PoolBuffer snapshot = packet.borrow();
            enqueueEarlyOneRtt(snapshot);

            packet.buf().position(packet.buf().limit());
            return;
        }

        if (tlsMetadata == null || tlsMetadata.clientApplicationKeys.key() == null) {
            // RFC 9000: Silently discard packets when 1-RTT keys are not available
            logger.warn("No 1-RTT keys available for CID: {}, discarding packet", connectionId);
            packet.buf().position(packet.buf().limit());
            return;
        }

        // Parse short header — use the HP key pre-derived in TlsMetadata
        // (RFC 9001 Section 5.4: 1-RTT level hp_key derived via "quic hp")
        QuicPacketHeader header = QuicPacketHeader.parse(packet.buf(), tlsMetadata.clientApplicationHeaderProtection);
        logger.debug("Processing 1-RTT packet: CID={}, packetNumber={}, ", header.destinationCid, header.packetNumber);

        // Rotate secrets based on the Key Phase flag.
        byte phase = (byte) (header.flags >> 2 & 0x01);
        boolean differentKeyPhase = phase != tlsMetadata.currentPhase;
        if (differentKeyPhase && header.packetNumber > tlsMetadata.lastPhaseSwitchPacketNumber) {
            try {
                rotateApplicationKeys(tlsMetadata);
                tlsMetadata.lastPhaseSwitchPacketNumber = header.packetNumber;
            } catch (QuicCrypto.CryptoException e) {
                logger.error("Could not rotate secrets", e);
                packet.buf().position(packet.buf().limit());
                return;
            }
        }

        // Update idle timeout on activity
        updateTimeout();

        PoolBuffer plaintext;

        try {
            if (differentKeyPhase && header.packetNumber < tlsMetadata.lastPhaseSwitchPacketNumber) {
                plaintext = decryptAeadInPlace(packet, header, packet.buf().remaining(), tlsMetadata.prevClientApplicationKeys);
            } else {
                plaintext = decryptAeadInPlace(packet, header, packet.buf().remaining(), tlsMetadata.clientApplicationKeys);
            }
        } catch (Exception e) {
            logger.warn("1-RTT packet decryption/authentication failed for CID: {}, discarding: {}", connectionId, e.getMessage());
            packet.buf().position(packet.buf().limit());
            return;
        }

        // Track received packet in Application space
        applicationSpace.onPacketReceived(header.packetNumber);

        boolean needsAck = false;

        while (plaintext.buf().hasRemaining()) {
            byte frameType = plaintext.buf().get();

            if (frameType == 0x02 || frameType == 0x03) { // ACK or ACK_ECN
                logger.info("Received 1-RTT ACK for CID: {}", connectionId);
                processAckFrame(plaintext.buf(), applicationSpace, frameType);
            } else if (frameType == 0x1c || frameType == 0x1d) { // CONNECTION_CLOSE
                String closeType = frameType == 0x1c ? "QUIC" : "Application";
                logger.info("Received CONNECTION_CLOSE ({}) for CID: {}", closeType, connectionId);
                parseConnectionCloseFrame(plaintext.buf(), frameType);

                needsAck = true; // CONNECTION_CLOSE is ack-eliciting
                break; // CONNECTION_CLOSE terminates the packet
            } else if (frameType >= FRAME_TYPE_STREAM && frameType <= 0x0f) { // Stream-related frames: STREAM (0x08-0x0f)
                logger.info("Got Stream frame CID {} frame type {}", connectionId, frameType);

                boolean hasOffset = (frameType & 0x04) != 0;
                boolean hasLength = (frameType & 0x02) != 0;
                boolean fin = (frameType & 0x01) != 0;

                long streamId = QuicVarint.read(plaintext.buf());
                long offset = (hasOffset) ? QuicVarint.read(plaintext.buf()) : 0;
                long length = (hasLength) ? QuicVarint.read(plaintext.buf()) : plaintext.buf().remaining();

//                byte[] data = new byte[(int) Math.min(length, plaintext.remaining())];
//                plaintext.get(data);
//                log.info(ANSIConstants.RED_FG,"STREAM frame received. Stream id {}, data: {}, str: {}", streamId, HexFormat.of().formatHex(data), new String(data));

                if (connectionStreamManager != null) {
                    connectionStreamManager.onStreamFrame(new StreamFrameData(streamId, offset, plaintext.borrow(), fin));
                } else {
                    logger.warn("No stream frame listener set, dropping frame type 0x{}", String.format("%02x", frameType));
                }

                plaintext.buf().position(plaintext.buf().position() + (int) length);

                needsAck = true; // All stream frames are ack-eliciting

            } else if (frameType == FRAME_TYPE_RESET_STREAM) { // RESET_STREAM
                long streamId  = QuicVarint.read(plaintext.buf());
                long errorCode = QuicVarint.read(plaintext.buf());
                long finalSize = QuicVarint.read(plaintext.buf());
                logger.info("Received RESET_STREAM CID={} streamId={} errorCode={} finalSize={}",
                        connectionId, streamId, errorCode, finalSize);
                if (connectionStreamManager != null) {
                    connectionStreamManager.onStreamFrame(new ResetStreamFrameData(streamId, errorCode, finalSize));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_STOP_SENDING) { // STOP_SENDING
                long streamId  = QuicVarint.read(plaintext.buf());
                long errorCode = QuicVarint.read(plaintext.buf());
                logger.info("Received STOP_SENDING CID={} streamId={} errorCode={}",
                        connectionId, streamId, errorCode);
                if (connectionStreamManager != null) {
                    connectionStreamManager.onStreamFrame(new StopSendingFrameData(streamId, errorCode));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_MAX_STREAM_DATA) { //MAX_STREAM_DATA
                long streamId = QuicVarint.read(plaintext.buf());
                long maxStramData = QuicVarint.read(plaintext.buf());
                logger.info("Received MAX_STREAM_DATA {} {}", streamId, maxStramData);
                if (connectionStreamManager != null) {
                    connectionStreamManager.onStreamFrame(new MaxStreamDataFrameData(streamId, maxStramData));
                }
            } else if (frameType == FRAME_TYPE_MAX_STREAMS_BIDI) { //MAX_STREAMS (Bidirectional)
                long maxStreams = QuicVarint.read(plaintext.buf());
                logger.info("Received MAX_STREAMS (bidirectional) CID={} max={}", connectionId, maxStreams);
                if (connectionStreamManager != null) {
                    connectionStreamManager.onStreamFrame(new MaxStreamsFrameData(maxStreams, true));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_MAX_STREAMS_UNI) { //MAX_STREAMS (Unidirectional)
                long maxStreams = QuicVarint.read(plaintext.buf());
                logger.info("Received MAX_STREAMS (unidirectional) CID={} max={}", connectionId, maxStreams);
                if (connectionStreamManager != null) {
                    connectionStreamManager.onStreamFrame(new MaxStreamsFrameData(maxStreams, false));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_STREAM_DATA_BLOCKED) { //STREAM_DATA_BLOCKED
                long streamId  = QuicVarint.read(plaintext.buf());
                long dataLimit = QuicVarint.read(plaintext.buf());
                logger.info("Received STREAM_DATA_BLOCKED CID={} streamId={} limit={}", connectionId, streamId, dataLimit);
                if (connectionStreamManager != null) {
                    connectionStreamManager.onStreamFrame(new StreamDataBlockedFrameData(streamId, dataLimit));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_STREAMS_BLOCKED_BIDI) { //STREAMS_BLOCKED (Bidirectional)
                long streamLimit = QuicVarint.read(plaintext.buf());
                logger.info("Received STREAMS_BLOCKED (bidirectional) CID={} limit={}", connectionId, streamLimit);
                if (connectionStreamManager != null) {
                    connectionStreamManager.onStreamFrame(new StreamsBlockedFrameData(streamLimit, true));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_STREAMS_BLOCKED_UNI) { //STREAMS_BLOCKED (Unidirectional)
                long streamLimit = QuicVarint.read(plaintext.buf());
                logger.info("Received STREAMS_BLOCKED (unidirectional) CID={} limit={}", connectionId, streamLimit);
                if (connectionStreamManager != null) {
                    connectionStreamManager.onStreamFrame(new StreamsBlockedFrameData(streamLimit, false));
                }
                needsAck = true;
            } else if (frameType == 0x06) { // CRYPTO
                long cryptoOffset = QuicVarint.read(plaintext.buf());
                long cryptoLength = QuicVarint.read(plaintext.buf());
                int cryptoDataLen = (int) Math.min(cryptoLength, plaintext.buf().remaining());
                plaintext.buf().position(plaintext.buf().position() + cryptoDataLen);
                logger.info("Received 1-RTT CRYPTO frame CID={} offset={} length={}",
                        connectionId, cryptoOffset, cryptoLength);
                needsAck = true;
            } else if (frameType == 0x07) { // NEW_TOKEN
                long tokenLength = QuicVarint.read(plaintext.buf());
                int tokenDataLen = (int) Math.min(tokenLength, plaintext.buf().remaining());
                plaintext.buf().position(plaintext.buf().position() + tokenDataLen);
                logger.info("Received NEW_TOKEN CID={} tokenLength={}", connectionId, tokenLength);
                needsAck = true;
            } else if (frameType == 0x10) { // MAX_DATA
                // RFC 9000 Section 19.9: maximum_data(varint)
                long maxData = QuicVarint.read(plaintext.buf());
                logger.info("Received MAX_DATA CID={} maxData={}", connectionId, maxData);
                needsAck = true;
            } else if (frameType == FRAME_TYPE_DATA_BLOCKED) { // DATA_BLOCKED
                // RFC 9000 Section 19.12: maximum_data(varint)
                long dataLimit = QuicVarint.read(plaintext.buf());
                logger.info("Received DATA_BLOCKED CID={} dataLimit={}", connectionId, dataLimit);
                needsAck = true;
            } else if (frameType == 0x18) { // NEW_CONNECTION_ID
                // RFC 9000 Section 19.15: sequence_number(varint) + retire_prior_to(varint) +
                //   length(1) + connection_id(*) + stateless_reset_token(16)
                long seqNum         = QuicVarint.read(plaintext.buf());
                long retirePriorTo  = QuicVarint.read(plaintext.buf());
                int cidLen          = plaintext.buf().get() & 0xFF;
                plaintext.buf().position(plaintext.buf().position() + cidLen); // skip connection_id
                plaintext.buf().position(plaintext.buf().position() + 16);     // skip stateless_reset_token
                log.error(ANSIConstants.RED_FG,
                        "Connection migration initiated but NOT SUPPORTED! CID={} seqNum={} retirePriorTo={}",
                        connectionId, seqNum, retirePriorTo);
                needsAck = true;
            } else if (frameType == 0x19) { // RETIRE_CONNECTION_ID
                // RFC 9000 Section 19.16: sequence_number(varint)
                long seqNum = QuicVarint.read(plaintext.buf());
                logger.info("Received RETIRE_CONNECTION_ID CID={} seqNum={}", connectionId, seqNum);
                needsAck = true;
            } else if (frameType == 0x1a) { // PATH_CHALLENGE
                // RFC 9000 Section 19.17: data(8 bytes)
                plaintext.buf().position(plaintext.buf().position() + 8);
                logger.info("Received PATH_CHALLENGE CID={}", connectionId);
                needsAck = true;
            } else if (frameType == 0x1b) { // PATH_RESPONSE
                // RFC 9000 Section 19.18: data(8 bytes)
                plaintext.buf().position(plaintext.buf().position() + 8);
                logger.info("Received PATH_RESPONSE CID={}", connectionId);
                needsAck = true;
            } else if (frameType == 0x1e) { // HANDSHAKE_DONE
                logger.debug("Received HANDSHAKE_DONE from client (unexpected)");
                needsAck = true;
            } else if (frameType == 0x30 || frameType == 0x31) { // DATAGRAM
                // RFC 9221: optional length(varint) + data(*)
                // 0x30 = no length field (consume rest of packet), 0x31 = length field present
                if (frameType == 0x31) {
                    long datagramLength = QuicVarint.read(plaintext.buf());
                    int datagramDataLen = (int) Math.min(datagramLength, plaintext.buf().remaining());
                    plaintext.buf().position(plaintext.buf().position() + datagramDataLen);
                    logger.info("Received DATAGRAM CID={} length={}", connectionId, datagramLength);
                } else {
                    int datagramDataLen = plaintext.buf().remaining();
                    plaintext.buf().position(plaintext.buf().position() + datagramDataLen);
                    logger.info("Received DATAGRAM (no-length) CID={} length={}", connectionId, datagramDataLen);
                }
                needsAck = true;
            } else if (frameType == 0x00) { // PADDING
                // RFC 9000 Section 19.1: consume all consecutive PADDING bytes
                while (plaintext.buf().hasRemaining() && plaintext.buf().get(plaintext.buf().position()) == 0x00) {
                    plaintext.buf().get();
                }
            } else if (frameType == 0x01) { // PING
                logger.debug("Received PING for CID: {}", connectionId);
                updateTimeout();
                needsAck = true;
            } else {
                logger.debug("Unknown 1-RTT frame type: 0x{}", String.format("%02x", frameType));
                plaintext.buf().position(plaintext.buf().limit());
                break; // Cannot safely skip an unknown frame; stop parsing
            }
        }

        plaintext.release();

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
    void processInitialAndRespond(PoolBuffer datagram) {
        if (state.get() == State.CLOSING || state.get() == State.CLOSED) {
            logger.warn("Connection is closing, no incoming packets processed");
            datagram.buf().position(datagram.buf().limit());
            return;
        }

        logger.debug("Processing Initial packet for CID: {} in state: {}", connectionId, state);

        // Step 1: Process Initial packet
        PoolBuffer frames = processInitialPacket(datagram);

        boolean needAck = false;

        while (frames != null && frames.buf().hasRemaining()) {
            byte frameType = frames.buf().get();

            if (frameType == 0x02 || frameType == 0x03) { // ACK or ACK_ECN
                logger.info("Received Initial ACK for CID: {}", connectionId);
                processAckFrame(frames.buf(), initialSpace, frameType); // ACK for Initial packets
            } else if (frameType == 0x00) { // PADDING
                // Skip padding
            } else if (frameType == 0x01) { // PING
                logger.info("Received Initial PING for CID: {}", connectionId);
                needAck = true;
                updateTimeout();
            } else if (frameType == 0x06) { // CRYPTO
                needAck = true;

                long offset = QuicVarint.read(frames.buf());
                long length = QuicVarint.read(frames.buf());

                logger.info("Received Initial CRYPTO frame for CID: {}, offset={}, length={}",
                        connectionId, offset, length);

                if(state.get() != State.INITIAL) {
                    frames.buf().position(Math.min(frames.buf().limit(), frames.buf().position() + (int) length));
                    logger.info("State is {}, skipping crypto frame.", state);
                } else {
                    try {
                        rebuildCryptoFrame(offset, length, frames, this::extractTlsMeta);
                    } catch (IllegalStateException | IllegalArgumentException e) {
                        setState(State.CLOSING);
                        sendConnectionCloseAndUpdateState(ERR_PROTOCOL_VIOLATION, "malformed crypto frame", false);
                        logger.warn("Got inconsistent frame: {}", e.getMessage());
                    }
                }
            } else if (frameType == 0x1c || frameType == 0x1d) { // CONNECTION_CLOSE
                needAck = true;

                String closeType = frameType == 0x1c ? "QUIC" : "Application";
                logger.info("Received CONNECTION_CLOSE ({}) for CID: {}", closeType, connectionId);
                parseConnectionCloseFrame(frames.buf(), frameType);


                break;
            }
        }

        if (frames != null) {
            frames.release();
        }

        if (needAck) {
            sendInitialAck();
        }

        logger.debug("Initial packet processed for connection {}", connectionId);

        if (state.get() == State.INITIAL && tlsMetadata.clientMetadata != null) {
            try {
                logger.info("Connection CID: {} got complete ClientHello, proceeding with handshake...", connectionId);

                sendInitialResponse();

                QuicCrypto.generateHandshakeSecrets(tlsMetadata);

                // Generate Handshake response with server Certificate/Finished.
                // This updates the transcript with: Certificate, CertificateVerify, server Finished.
                sendHandshakePacket();

                // Transition to HANDSHAKE state
                setState(State.HANDSHAKE);
            } catch (Exception e) {
                logger.error("Failed to send Handshake response", e);
            }
        } else {
            if (state.get() != State.INITIAL) {
                logger.warn("Connection {}: already in state {}, initial packets not expected", connectionId, state);
            }
        }
    }

    private void rebuildCryptoFrame(long offset, long length, PoolBuffer frames, Consumer<ByteBuffer> readyFrameConsumer) {
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

            copyNewFields(tlsMetadata, derivedMetadata);

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
            sendConnectionCloseAndUpdateState(ERR_PROTOCOL_VIOLATION, "ClientHello validation failed", false);
        }
    }

    private static void copyNewFields(QuicCrypto.TlsMetadata tlsMetadata, QuicCrypto.TlsMetadata derivedMetadata) {
        for (Field field : QuicCrypto.TlsMetadata.class.getDeclaredFields()) {
            if (field.canAccess(derivedMetadata) && !Modifier.isFinal(field.getModifiers())) {
                try {
                    Object val = field.get(derivedMetadata);
                    if (val != null) {
                        field.set(tlsMetadata, val);
                    }
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }

    public void closeConnection(QuicTransportError e, String reason) {
        sendConnectionCloseAndUpdateState(e.code(), reason, true);
    }
    public void closeConnection(long errorCode, String reason) {
        sendConnectionCloseAndUpdateState(errorCode, reason, true);
    }

    void sendConnectionCloseAndUpdateState(QuicTransportError e, String reason) {
        sendConnectionCloseAndUpdateState(e.code(), reason, false);
    }

    private void sendConnectionCloseAndUpdateState(long errorCode, String reason, boolean ext) {
        try {
            PacketNumberSpace.PacketPhase phase = switch (state.get()) {
                case INITIAL -> PacketNumberSpace.PacketPhase.INITIAL;
                case HANDSHAKE ->  PacketNumberSpace.PacketPhase.HANDSHAKE;
                default -> PacketNumberSpace.PacketPhase.APPLICATION;
            };

            setState(State.CLOSING);
            ByteBuffer byteBuffer = ByteBuffer.allocate(2018);
            QuicFrameBuilder.writeConnectionCloseFrame(byteBuffer, errorCode, reason);

            logger.debug("Sending CONNECTION_CLOSE Initial packet");
            if (ext) {
                enqueueApplicationData(byteBuffer);
            } else {
                sendPacket(byteBuffer, phase);
            }
            logger.info("Sent CONNECTION_CLOSE for CID: {}, transitioning to CLOSING", connectionId);
        } catch (Exception encryptEx) {
            logger.error("Failed to encrypt CONNECTION_CLOSE packet", encryptEx);
            setState(State.CLOSED);
        }
    }

    private void sendHelloRetryRequest(short prefferedGroupId) {
        ByteBuffer hrrFrame = ByteBuffer.allocate(128);

        writeHelloRetryRequest(hrrFrame, prefferedGroupId);
        QuicCrypto.applyHelloRetryRequestToTranscript(tlsMetadata, hrrFrame);

        logger.debug("Sending HelloRetryRequest Initial packet");
        sendInitialPacket(hrrFrame);
    }

    private void sendPacket(ByteBuffer payload, PacketNumberSpace.PacketPhase phase) {
        PacketNumberSpace space = switch (phase) {
            case INITIAL -> initialSpace;
            case HANDSHAKE -> handshakeSpace;
            case APPLICATION -> applicationSpace;
        };

        long packetNumber = space.allocatePacketNumber();

        PoolBuffer completePacket;
        try {
            completePacket = switch (phase) {
                case INITIAL -> QuicPacketBuilder.buildInitialPacket(
                        clientCid,      // DCID = connection ID
                        connectionIdBytes,      // SCID = connection ID (server uses same)
                        packetNumber,
                        payload.duplicate(),            // Plaintext payload
                        tlsMetadata.serverInitialKeys
                    );
                case HANDSHAKE -> QuicPacketBuilder.buildHandshakePacket(
                        clientCid,      // DCID = connection ID
                        connectionIdBytes,      // SCID = connection ID (server uses same)
                        packetNumber,
                        payload.duplicate(),            // Plaintext payload
                        tlsMetadata.serverHandshakeKeys
                    );
                case APPLICATION ->  QuicPacketBuilder.build1RttPacket(
                        clientCid,
                        packetNumber,
                        payload.duplicate(),          // Plaintext payload
                        tlsMetadata.serverApplicationKeys,
                        tlsMetadata.serverApplicationHeaderProtection,
                        tlsMetadata.currentPhase
                );
            };
        } catch (QuicCrypto.CryptoException e) {
            logger.error("Failed to build Initial packet", e);
            return;
        }

        logger.debug("Sending {} packet {}: {} bytes", phase, packetNumber, completePacket.buf().remaining());

        // Track sent packet: store UNENCRYPTED payload for retransmission
        space.onPacketSent(packetNumber, payload, true);

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
    private void sendInitialResponse() throws IOException {
        // Create ServerHello — uses the server's ephemeral public key already stored in tlsMetadata
        int headersReservedSize = MAX_LONG_HEADER_LENGTH + INITIAL_PACKET_TOKEN_LENGTH + CRYPTO_FRAME_MAX_HEADER_LENGTH;

        ByteBuffer serverHello = ByteBuffer.allocate(4096);

        serverHello.position( headersReservedSize);

        ChunkedOutputStreamWithAmendmentsImpl outs = new ChunkedOutputStreamWithAmendmentsImpl(serverHello,
                (int) (tlsMetadata.clientMetadata.maxUdpPayloadSize - 17 - 16),
                (buffer, offset) -> {
                    QuicFrameBuilder.prependCryptoFrameHeader(offset, buffer);
                    ByteBuffer wrappedChunk = buffer.duplicate();

                    int chunkEnd = buffer.limit();
                    buffer.limit(buffer.capacity());
                    buffer.position(chunkEnd + headersReservedSize + GCM_TAG_LENGTH);
                    return wrappedChunk;
                }
            );
        TranscryptHashSupport transcryptHashSupport = new TranscryptHashSupport(outs, this::updateTranscript);

        transcryptHashSupport.startHashMessage("ServerHello");
        writeServerHello(outs, tlsMetadata);

        outs.close();
        transcryptHashSupport.finish();

        for (ByteBuffer chunk : outs.readyChunks()) {
            sendInitialPacket(chunk);
            logger.debug("Sending ServerHello Initial packet");
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
    private void sendHandshakePacket() throws Exception {
        ByteBuffer frameBuffer = ByteBuffer.allocate(4096);
        int headersReservedSize = MAX_LONG_HEADER_LENGTH + CRYPTO_FRAME_MAX_HEADER_LENGTH + PING_FRAME_LENGTH;
        frameBuffer.position(headersReservedSize);

        ChunkedOutputStreamWithAmendmentsImpl out = new ChunkedOutputStreamWithAmendmentsImpl(frameBuffer, (int) tlsMetadata.clientMetadata.maxUdpPayloadSize - 16,
                (buffer, offset) -> {
                    QuicFrameBuilder.prependCryptoFrameHeader(offset, buffer);
                    QuicFrameBuilder.prependPingFrame(buffer);
                    ByteBuffer wrappedChunk = buffer.duplicate();

                    int chunkEnd = buffer.limit();
                    buffer.limit(buffer.capacity());
                    buffer.position(chunkEnd + headersReservedSize + GCM_TAG_LENGTH);
                    return wrappedChunk;
                });

        TranscryptHashSupport transcryptUpdater = new TranscryptHashSupport(out, this::updateTranscript);
        // ── 1. EncryptedExtensions ────────────────────────────────────────────
        transcryptUpdater.startHashMessage("EncryptedExtensions");
        QuicCrypto.putEncryptedExtensions(tlsMetadata, connectionId, out);

        // ── 2. Certificate ────────────────────────────────────────────────────
        transcryptUpdater.startHashMessage("Certificate");
        QuicCrypto.putCertificate(out);

        // ── 3. CertificateVerify ──────────────────────────────────────────────
        // Transcript now covers EE + Cert; CertificateVerify signs over that hash.
        transcryptUpdater.startHashMessage("CertificateVerify");
        QuicCrypto.putCertificateVerify(tlsMetadata, out);

        // ── 4. Finished ───────────────────────────────────────────────────────
        transcryptUpdater.startHashMessage("server Finished");
        QuicCrypto.createServerFinished(tlsMetadata, out);

        out.close();
        transcryptUpdater.finish();

        for (ByteBuffer chunk : out.readyChunks()) {
            sendHandshakePacket(chunk);
        }
    }

    private static @NonNull ByteBuffer lastPutPart(PoolBuffer poolBuffer, int pos) {
        return poolBuffer.buf().duplicate().position(pos).limit(poolBuffer.buf().position());
    }

    /**
     * Feeds a TLS handshake message into the running transcript hash and logs it.
     * The buffer's position is not advanced (uses a duplicate for reading).
     */
    private void updateTranscript(ByteBuffer message, String messageName) {
        tlsMetadata.updateTranscript(message);
    }

    /**
     * Creates 1-RTT (Short Header) packet with HANDSHAKE_DONE frame.
     * This signals to the client that the handshake is complete.
     */
    private void sendHandshakeDonePacket() throws Exception {
        // Create HANDSHAKE_DONE frame (type 0x1e)
        ByteBuffer frame =  ByteBuffer.allocate(OUTBOUND_APP_QUEUE_SIZE);
        QuicFrameBuilder.createHandshakeDoneFrame(frame);
        frame.put((byte) 0x01); // PING
        frame.flip();

        logger.debug("Sending HANDSHAKE_DONE frame in 1-RTT packet");
        sendApplicationPacket(frame);
    }

    private void sendInitialAck() {
        ByteBuffer frameBuffer = ByteBuffer.allocate(256);
        QuicFrameBuilder.writeAckFrame(initialSpace, frameBuffer);
        logger.debug("Sending ACK Initial packet");
        sendInitialPacket(frameBuffer);
    }
    private void sendHandshakeAck() {
        ByteBuffer frameBuffer = ByteBuffer.allocate(256);
        QuicFrameBuilder.writeAckFrame(handshakeSpace, frameBuffer);
        logger.debug("Sending Handshake ACK");
        sendHandshakePacket(frameBuffer);
    }
    private void send1RttAck() {
        ByteBuffer frameBuffer = ByteBuffer.allocate(256);
        QuicFrameBuilder.writeAckFrame(applicationSpace, frameBuffer);
        logger.debug("Sending 1-RTT ACK");
        sendApplicationPacket(frameBuffer);
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

        space.onAckReceived(largestAcked, ackRanges, ackDelay, connectionStreamManager);

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
        if (state.get() != State.CLOSED && state.get() != State.CLOSING) {
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
            ByteBuffer frame = QuicPacketBuilder.writeStatelessResetFrame(connectionId, incomingPacketSize);
            sendInitialPacket(frame);
            logger.info("Sent Stateless Reset ({} bytes)", frame.remaining());
        } catch (Exception e) {
            logger.error("Failed to send Stateless Reset", e);
        }
    }
}
