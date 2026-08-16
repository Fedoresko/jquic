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
package org.jquic.quic;

import org.jctools.queues.MessagePassingQueue;
import org.jquic.quic.buffers.BufferPool;
import org.jquic.quic.buffers.ChunkedOutputStreamWithAmendments;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.buffers.TranscryptHashSupport;
import org.jquic.quic.crypto.NativeCrypto;
import org.jquic.quic.crypto.QuicCrypto;
import org.jquic.quic.linux.ECT;
import org.jquic.quic.streamapi.CongestionControl;
import org.jquic.quic.streamapi.ConnectionStreamManager;
import org.jquic.quic.streamapi.QuicApplicationProtocol;
import org.jquic.quic.streamapi.frames.*;
import org.jquic.quic.streamapi.impl.ApplicationData;
import org.jquic.quic.streamapi.impl.QuicStreamEngineImpl;
import org.jquic.quic.streamapi.impl.StreamManager;
import org.jquic.quic.struct.TimeoutHeap;
import org.jquic.quic.struct.TriStateQueue;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.jquic.quic.QuicConnection.State.*;
import static org.jquic.quic.QuicFrameBuilder.*;
import static org.jquic.quic.crypto.QuicCrypto.GCM_TAG_LENGTH;
import static org.jquic.quic.streamapi.impl.StreamFrameWriter.*;

/**
 * Represents a QUIC connection with its cryptographic state and metadata.
 */
public class QuicConnection implements TimeoutHeap.Entry {
    private static final Logger logger = LoggerFactory.getLogger(QuicConnection.class);

    /** Maximum number of early 1-RTT packets buffered before ESTABLISHED. */
    private static final int MAX_EARLY_1RTT_QUEUE = 32;

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
    private static final long DEFAULT_IDLE_TIMEOUT_MS = QuicProperties.DEFAULT_IDLE_TIMEOUT_MS; // 30 seconds
    private static final long MAX_IDLE_TIMEOUT_MS = 600_000; // 10 minutes

    private final long connectionId;
    private final ByteBuffer connectionIdBytes;
    private final SocketAddress remoteAddress;
    private final AtomicReference<State> state = new AtomicReference<>(INITIAL);
    public ConnectionMetadata connectionMetadata = new ConnectionMetadata();
    private int timeoutHeapIndex = -1;
    private ConnectionStreamManager connectionStreamManager;
    private long currentTimestamp;
    private final byte[] statelessResetToken;
    private QuicVersion quicVersion;

    // ALPN - negotiated application protocol (RFC 9001 Section 8.1)
    private String negotiatedProtocol = null;

    // Timeout tracking (RFC 9000 Section 10.1)
    private long idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS;
    private volatile long timeoutTimestamp;

    // Packet number spaces (RFC 9000 Section 12.3)
    private final PacketNumberSpace initialSpace = new PacketNumberSpace(PacketNumberSpace.PacketPhase.INITIAL);
    private final PacketNumberSpace handshakeSpace = new PacketNumberSpace(PacketNumberSpace.PacketPhase.HANDSHAKE);
    private final PacketNumberSpace applicationSpace = new PacketNumberSpace(PacketNumberSpace.PacketPhase.APPLICATION);

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
    private final Deque<OutboundPacket> outboundQueue = new ArrayDeque<>();
    private final MessagePassingQueue<TriStateQueue<ApplicationData>> wakeQueue;
    private CryptoFrameRebuilder cryptoFrameRebuilder;
    byte[] clientCid;
    private final SelectorThread selector;
    private CongestionControl congestionControl;

    public QuicConnection(long connectionId, QuicVersion version, SocketAddress remoteAddress, MessagePassingQueue<TriStateQueue<ApplicationData>> wakeQueue, SelectorThread selector) {
        this.connectionId = connectionId;
        this.connectionIdBytes = ByteBuffer.allocate(8).putLong(connectionId);
        this.remoteAddress = remoteAddress;
        this.wakeQueue = wakeQueue;
        this.state.set(INITIAL);
        this.currentTimestamp = System.currentTimeMillis();
        this.timeoutTimestamp = idleTimeoutMs + currentTimestamp;
        this.selector = selector;
        this.quicVersion = version;
        statelessResetToken = QuicCrypto.generateStatelessResetToken(ByteBuffer.allocate(8).putLong(connectionId).array());
        logger.info("Connection {} initial timeout set to {}", connectionId, timeoutTimestamp);
    }

    public BufferPool getBufferPool() {
        return selector.getBufferPool();
    }

    @Nullable
    public CongestionControl getCongestionControl() { return  congestionControl; }

    public void setCurrentTimestamp(long timestamp) {
        this.currentTimestamp = timestamp;
    }

    public void setConnectionStreamManager(ConnectionStreamManager connectionStreamManager) {
        this.connectionStreamManager = connectionStreamManager;
    }

    /**
     * Sends a frame immediately over the connection.
     * Wraps the frame in a 1-RTT packet, encrypts it, updates PacketNumberSpace, and sends to socket.
     *
     * @param frame The frame to send (already encoded)
     */
    boolean send1RttPacket(PoolBuffer frame) {
        if (state.get() != State.ESTABLISHED) {
            logger.warn("Cannot send frame, connection not established (state: {})", state);
            return false;
        }

        sendApplicationPacket(frame);
        return true;
    }

    /**
     * Polls one outbound packet from the connection's outbound queue.
     * The owning {@code SelectorThread} calls this after every processing cycle
     * to drain any packets that were produced internally (early-1RTT replay,
     * {@link #send1RttPacket}, etc.) and send them to the {@code DatagramChannel}.
     *
     * @return the next ready-to-send encrypted packet, or {@code null} if the queue is empty
     */
    OutboundPacket pollOutbound() {
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
            snapshot.release();
            logger.warn("Early 1-RTT queue full for CID: {}, dropping packet", connectionId);
        }
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
        this.timeoutTimestamp = currentTimestamp + idleTimeoutMs;
        logger.debug("Connection {} tiemout updated to {}", connectionId, timeoutTimestamp);
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

        if (state == State.HANDSHAKE && previousState == INITIAL) {
            initialSpace.discardSentPackets();
        }

        // Register with stream engine when transitioning to ESTABLISHED
        if (state == State.ESTABLISHED && previousState != State.ESTABLISHED) {
            handshakeSpace.discardSentPackets();
            if (negotiatedProtocol != null) {
                QuicStreamEngineImpl engine =
                        QuicEngine.getStreamEngineInternal();
                if (engine != null) {
                    setConnectionStreamManager(engine.createConnection(connectionId, this, negotiatedProtocol, wakeQueue));
                    QuicApplicationProtocol protocol = engine.getProtocol(negotiatedProtocol);
                    if (protocol != null) {
                        applicationSpace.setTimeWindowMs(protocol.getCongestionControl().timeWindowMs());
                        congestionControl = protocol.getCongestionControl();
                    }

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
                        process1RttPacket(snapshot, 0);
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
            PacketNumberSpace space = switch (previousState) {
                case INITIAL -> initialSpace;
                case HANDSHAKE -> handshakeSpace;
                case ESTABLISHED -> applicationSpace;
                default -> null;
            };

            if (state == State.CLOSING) {
                this.timeoutTimestamp = currentTimestamp + 3 * space.getPTO();
            }

            if (connectionStreamManager != null) {
                connectionStreamManager.onConnectionClose();
            }

            QuicStreamEngineImpl engine =
                    QuicEngine.getStreamEngineInternal();
            if (engine != null) {
                engine.removeConnection(connectionId, null, null);
                logger.info("Unregistered connection {} from stream engine", connectionId);
            }
        }

        if (state == CLOSED) {
            try {
                initialSpace.discardSentPackets();
                handshakeSpace.discardSentPackets();
                applicationSpace.discardSentPackets();

                if (connectionMetadata.clientApplicationCrypto != null) {
                    connectionMetadata.clientApplicationCrypto.close();
                    connectionMetadata.clientApplicationCrypto = null;
                }
                if (connectionMetadata.clientHandshakeCrypto != null) {
                    connectionMetadata.clientHandshakeCrypto.close();
                    connectionMetadata.clientHandshakeCrypto = null;
                }
                if (connectionMetadata.clientInitialCrypto != null) {
                    for (NativeCrypto crypto : connectionMetadata.clientInitialCrypto.values()) {
                        crypto.close();
                    }
                    connectionMetadata.clientInitialCrypto = null;
                }
                if (connectionMetadata.serverApplicationCrypto != null) {
                    connectionMetadata.serverApplicationCrypto.close();
                    connectionMetadata.serverApplicationCrypto = null;
                }
                if (connectionMetadata.serverHandshakeCrypto != null) {
                    connectionMetadata.serverHandshakeCrypto.close();
                    connectionMetadata.serverHandshakeCrypto = null;
                }
                if (connectionMetadata.serverInitialCrypto != null) {
                    for (NativeCrypto crypto : connectionMetadata.serverInitialCrypto.values()) {
                        crypto.close();
                    }
                    connectionMetadata.serverInitialCrypto = null;
                }
            } catch (Exception ex) {
                logger.warn("Error while trying to close connection", ex);
            }
        }
    }

    ConnectionMetadata getTlsMetadata() {
        return connectionMetadata;
    }

    void setTlsMetadata(ConnectionMetadata connectionMetadata) {
        this.connectionMetadata = connectionMetadata;

        // Apply negotiated idle timeout from TLS handshake
        if (connectionMetadata.negotiatedIdleTimeoutMs > 0) {
            setIdleTimeout(connectionMetadata.negotiatedIdleTimeoutMs);
            logger.info("Applied negotiated idle timeout: {} ms for CID: {}",
                    connectionMetadata.negotiatedIdleTimeoutMs, connectionId);
        }
    }

    PacketNumberSpace getInitialSpace() {
        return initialSpace;
    }

    public PacketNumberSpace getApplicationSpace() {
        return applicationSpace;
    }

    private PoolBuffer processInitialPacket(PoolBuffer packet, int ecnFlags) {
        // RFC 9001 Section 5.2: Initial keys are derived deterministically from the DCID.
        // They carry no per-connection secret, so there is no need to store them as fields.
        int packetLen = packet.buf().remaining();
        QuicPacketHeader.PacketSummary packetSummary = QuicPacketHeader.parseSummary(packet.buf());

        Boolean isNewConnection = connectionMetadata.initializeKeys(quicVersion, packetSummary.dcid());
        
        if (isNewConnection == null) return null;

        // Parse masked header (packet number still protected)
        QuicPacketHeader header = QuicPacketHeader.parse(packet.buf(), connectionMetadata.clientInitialCrypto.get(packetSummary.version()), initialSpace.getLargestReceivedPacketNumber());
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

        initialSpace.onPacketReceived(currentTimestamp, header.packetNumber, ecnFlags);

        int remaining = packet.buf().remaining();
        try {
            return decryptAeadInPlace(packet, header, (int) header.payloadLength - header.pnLength, connectionMetadata.clientInitialCrypto.get(packetSummary.version()));
        } catch (Exception e) {
            // RFC 9000: Silently discard packets that fail decryption or tag verification
            logger.warn("Initial packet decryption/authentication failed for CID: {}, size: {} pn {} payloadLen {} issue stateless reset",
                    connectionId, remaining, header.packetNumber, header.payloadLength, e);
            logger.warn("Packet details: DCID {}, Pay len {}, PN {} remaining {}", header.destinationCid, header.payloadLength, header.packetNumber, remaining);
            if (isNewConnection) {
                sendStatelessReset(packetLen);
            }
            packet.release();
            return null;
        }
    }

    private PoolBuffer decryptAeadInPlace(PoolBuffer packet, QuicPacketHeader header, int length, NativeCrypto crypto) {
        PoolBuffer plaintext;
        int startLimit = packet.buf().limit();
        int packetEnd = packet.buf().position() + length;
        packet.buf().limit(packetEnd);

        plaintext = packet.borrow();
        // RFC 9001 Section 5.3: decryptAead verifies the GCM tag
        try {
            crypto.decryptAeadInPlace(plaintext.buf(), header.packetNumber, header.rawData);
        } catch (Exception e) {
            plaintext.release();
            throw new RuntimeException(e);
        } finally {
            packet.buf().limit(startLimit);
        }

        packet.buf().position(packetEnd);
        return plaintext;
    }

    /**
     * Processes client's Handshake packet and generates server's Handshake response.
     * This completes the QUIC handshake (RFC 9000 Section 7).
     * The packet buffer position is advanced as data is read.
     */
    void processHandshakePacket(PoolBuffer packet, int ecnFlags) {
        logger.debug("Processing Handshake packet for CID: {} in state: {}", connectionId, state);

        // RFC 9000: Handshake packets are only valid in HANDSHAKE state
        if (state.get() != State.HANDSHAKE) {
            logger.warn("Received Handshake packet for CID: {} in invalid state: {}, discarding",
                    connectionId, state);
            SelectorThread.skipPacket(packet.buf());
            return;
        }

        if (connectionMetadata == null) {
            // RFC 9000: Silently discard packets when TLS state is not ready
            logger.warn("No TLS metadata available for Handshake packet on CID: {}, discarding", connectionId);
            SelectorThread.skipPacket(packet.buf());
            return;
        }

        // Parse and decrypt packet - use the HP key pre-derived in TlsMetadata
        // (RFC 9001 Section 5.4: Handshake level hp_key derived via "quic hp")
        QuicPacketHeader header = QuicPacketHeader.parse(packet.buf(), connectionMetadata.clientHandshakeCrypto, handshakeSpace.getLargestReceivedPacketNumber());
        if (header == null) {
            // RFC 9000: Silently discard malformed packets
            logger.warn("Failed to parse Handshake packet header for CID: {}, discarding", connectionId);
            SelectorThread.skipPacket(packet.buf());
            return;
        }

        PoolBuffer frames;
        try {
            frames = decryptAeadInPlace(packet, header, (int) header.payloadLength - header.pnLength, connectionMetadata.clientHandshakeCrypto);
        } catch (Exception e) {
            packet.buf().position(packet.buf().limit());
            logger.warn("Handshake packet decryption/authentication failed for CID: {}, discarding",
                    connectionId, e);
            return;
        }

        // Track received packet in Handshake space
        handshakeSpace.onPacketReceived(currentTimestamp, header.packetNumber, ecnFlags);

        boolean needAck = false;

        while (frames.buf().hasRemaining()) {
            byte frameType = frames.buf().get();

            if (frameType == 0x02 || frameType == 0x03) { // ACK or ACK_ECN
                logger.debug("Received Handshake ACK for CID: {}", connectionId);
                processAckFrame(frames.buf(), initialSpace, frameType); // ACK for Initial packets
                updateTimeout();
            } else if (frameType == 0x00) { // PADDING
                // Skip padding
            } else if (frameType == 0x01) { //PING
                needAck = true;
                updateTimeout();
                logger.debug("Received Handshake PING for CID {} ", connectionId);
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
                sendConnectionCloseAndUpdateState(QuicTransportError.TLS_ERROR_HANDSHAKE_FAILURE.code(), "Unsupported handshake frame type", false);
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
                        connectionMetadata.clientHandshakeTrafficSecret,
                        connectionMetadata.transcriptHash()
                );

                if (!verified) {
                    logger.warn("Client Finished verification failed for CID: {}, discarding packet",
                            connectionId);
                    sendConnectionCloseAndUpdateState(QuicTransportError.TLS_ERROR_DECRYPT_ERROR, "Client Finished verification failed");
                    return;
                }

                logger.info("Client Finished verified successfully for CID: {}", connectionId);

                connectionMetadata.createApplicationKeys(quicVersion);
                logger.debug("1-RTT application keys derived (transcript complete)");

                connectionMetadata.updateTranscript(clientFinishedBytes);

                // Generate HANDSHAKE_DONE packet (uses server1RttSecret, now available)
                setState(State.ESTABLISHED);

                sendHandshakeDonePacket();

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
     */
    void process1RttPacket(PoolBuffer packet, int ecnFlags) {
        logger.debug("Processing 1-RTT packet for CID: {} in state: {}, len: {}", connectionId, state, packet.buf().remaining());

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

        if (connectionMetadata == null || connectionMetadata.clientApplicationCrypto == null) {
            // RFC 9000: Silently discard packets when 1-RTT keys are not available
            logger.warn("No 1-RTT keys available for CID: {}, discarding packet", connectionId);
            packet.buf().position(packet.buf().limit());
            return;
        }

        int remaining = packet.buf().remaining();

        // Parse short header - use the HP key pre-derived in TlsMetadata
        QuicPacketHeader header = QuicPacketHeader.parse(packet.buf(), connectionMetadata.clientApplicationCrypto, applicationSpace.getLargestReceivedPacketNumber());
        logger.debug("Processing 1-RTT packet: CID={}, packetNumber={}, ", header.destinationCid, header.packetNumber);

        // Rotate secrets based on the Key Phase flag.
        byte phase = (byte) (header.flags >> 2 & 0x01);
        boolean differentKeyPhase = phase != connectionMetadata.currentPhase;
        if (differentKeyPhase && header.packetNumber > connectionMetadata.lastPhaseSwitchPacketNumber) {
            try {
                connectionMetadata.rotateApplicationKeys(quicVersion);
                connectionMetadata.lastPhaseSwitchPacketNumber = header.packetNumber;
            } catch (Exception e) {
                logger.error("Could not rotate secrets", e);
                packet.buf().position(packet.buf().limit());
                return;
            }
        }

        // Update idle timeout on activity
        updateTimeout();

        PoolBuffer plaintext;
        int bodyLen = packet.buf().remaining();

        try {
            if (differentKeyPhase && header.packetNumber < connectionMetadata.lastPhaseSwitchPacketNumber) {
                plaintext = decryptAeadInPlace(packet, header, packet.buf().remaining(), connectionMetadata.prevClientApplicationCrypto);
            } else {
                plaintext = decryptAeadInPlace(packet, header, packet.buf().remaining(), connectionMetadata.clientApplicationCrypto);
            }
        } catch (Exception e) {
            logger.warn("1-RTT packet decryption/authentication failed for CID: {}, size: {} pn {} payloadLen {} issue stateless reset",
                    connectionId, remaining, header.packetNumber, bodyLen, e);
//            logger.warn("1-RTT packet decryption/authentication failed for CID: {}, discarding: {}", connectionId, e.getMessage());
            packet.buf().position(packet.buf().limit());
            return;
        }

        // Track received packet in Application space
        applicationSpace.onPacketReceived(currentTimestamp, header.packetNumber, ecnFlags);

        boolean needsAck = false;

        while (plaintext.buf().hasRemaining()) {
            byte frameType = plaintext.buf().get();

            if (frameType == 0x02 || frameType == 0x03) { // ACK or ACK_ECN
                logger.debug("Received 1-RTT ACK for CID: {}", connectionId);
                processAckFrame(plaintext.buf(), applicationSpace, frameType);
            } else if (frameType == 0x1c || frameType == 0x1d) { // CONNECTION_CLOSE
                String closeType = frameType == 0x1c ? "QUIC" : "Application";
                logger.info("Received CONNECTION_CLOSE ({}) for CID: {}", closeType, connectionId);
                parseConnectionCloseFrame(plaintext.buf(), frameType);

                needsAck = true; // CONNECTION_CLOSE is ack-eliciting
                break; // CONNECTION_CLOSE terminates the packet
            } else if (frameType >= FRAME_TYPE_STREAM && frameType <= 0x0f) { // Stream-related frames: STREAM (0x08-0x0f)

                boolean hasOffset = (frameType & 0x04) != 0;
                boolean hasLength = (frameType & 0x02) != 0;
                boolean fin = (frameType & 0x01) != 0;

                long streamId = QuicVarint.read(plaintext.buf());
                long offset = (hasOffset) ? QuicVarint.read(plaintext.buf()) : 0;
                long length = (hasLength) ? QuicVarint.read(plaintext.buf()) : plaintext.buf().remaining();

                if (connectionStreamManager != null) {
                    PoolBuffer borrowed = plaintext.borrow();
                    borrowed.buf().limit(borrowed.buf().position() + (int) length);
                    connectionStreamManager.onProtocolFrame(new StreamFrameData(streamId, offset, borrowed, fin));
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
                    connectionStreamManager.onProtocolFrame(new ResetStreamFrameData(streamId, errorCode, finalSize));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_STOP_SENDING) { // STOP_SENDING
                long streamId  = QuicVarint.read(plaintext.buf());
                long errorCode = QuicVarint.read(plaintext.buf());
                logger.info("Received STOP_SENDING CID={} streamId={} errorCode={}",
                        connectionId, streamId, errorCode);
                if (connectionStreamManager != null) {
                    connectionStreamManager.onProtocolFrame(new StopSendingFrameData(streamId, errorCode));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_MAX_STREAM_DATA) { //MAX_STREAM_DATA
                long streamId = QuicVarint.read(plaintext.buf());
                long maxStramData = QuicVarint.read(plaintext.buf());
                logger.info("Received MAX_STREAM_DATA {} {}", streamId, maxStramData);
                if (connectionStreamManager != null) {
                    connectionStreamManager.onProtocolFrame(new MaxStreamDataFrameData(streamId, maxStramData));
                }
            } else if (frameType == FRAME_TYPE_MAX_STREAMS_BIDI) { //MAX_STREAMS (Bidirectional)
                long maxStreams = QuicVarint.read(plaintext.buf());
                logger.info("Received MAX_STREAMS (bidirectional) CID={} max={}", connectionId, maxStreams);
                if (connectionStreamManager != null) {
                    connectionStreamManager.onProtocolFrame(new MaxStreamsFrameData(maxStreams, true));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_MAX_STREAMS_UNI) { //MAX_STREAMS (Unidirectional)
                long maxStreams = QuicVarint.read(plaintext.buf());
                logger.info("Received MAX_STREAMS (unidirectional) CID={} max={}", connectionId, maxStreams);
                if (connectionStreamManager != null) {
                    connectionStreamManager.onProtocolFrame(new MaxStreamsFrameData(maxStreams, false));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_STREAM_DATA_BLOCKED) { //STREAM_DATA_BLOCKED
                long streamId  = QuicVarint.read(plaintext.buf());
                long dataLimit = QuicVarint.read(plaintext.buf());
                logger.warn("Received STREAM_DATA_BLOCKED CID={} streamId={} limit={}", connectionId, streamId, dataLimit);
                if (connectionStreamManager != null) {
                    connectionStreamManager.onProtocolFrame(new StreamDataBlockedFrameData(streamId, dataLimit));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_STREAMS_BLOCKED_BIDI) { //STREAMS_BLOCKED (Bidirectional)
                long streamLimit = QuicVarint.read(plaintext.buf());
                logger.warn("Received STREAMS_BLOCKED (bidirectional) CID={} limit={}", connectionId, streamLimit);
                if (connectionStreamManager != null) {
                    connectionStreamManager.onProtocolFrame(new StreamsBlockedFrameData(streamLimit, true));
                }
                needsAck = true;
            } else if (frameType == FRAME_TYPE_STREAMS_BLOCKED_UNI) { //STREAMS_BLOCKED (Unidirectional)
                long streamLimit = QuicVarint.read(plaintext.buf());
                logger.warn("Received STREAMS_BLOCKED (unidirectional) CID={} limit={}", connectionId, streamLimit);
                if (connectionStreamManager != null) {
                    connectionStreamManager.onProtocolFrame(new StreamsBlockedFrameData(streamLimit, false));
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
                connectionStreamManager.onProtocolFrame(new MaxDataFrameData(maxData));
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
                logger.info("Connection migration initiated but NOT SUPPORTED! CID={} seqNum={} retirePriorTo={}",
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
                logger.info("Received HANDSHAKE_DONE from client (unexpected)");
                needsAck = true;
            } else if (frameType == 0x30 || frameType == 0x31) { // DATAGRAM
                // RFC 9221: optional length(varint) + data(*)
                // 0x30 = no length field (consume rest of packet), 0x31 = length field present
                if (frameType == 0x31) {
                    long datagramLength = QuicVarint.read(plaintext.buf());
                    int datagramDataLen = (int) Math.min(datagramLength, plaintext.buf().remaining());
                    PoolBuffer datagram = plaintext.borrow();
                    datagram.buf().limit(datagramDataLen);
                    connectionStreamManager.onProtocolFrame(new DatagramFrame(datagram));
                    plaintext.buf().position(plaintext.buf().position() + datagramDataLen);
                    logger.debug("Received DATAGRAM CID={} length={}", connectionId, datagramLength);
                } else {
                    int datagramDataLen = plaintext.buf().remaining();
                    PoolBuffer datagram = plaintext.borrow();
                    datagram.buf().limit(datagramDataLen);
                    connectionStreamManager.onProtocolFrame(new DatagramFrame(datagram));
                    plaintext.buf().position(plaintext.buf().position() + datagramDataLen);
                    logger.debug("Received DATAGRAM (no-length) CID={} length={}", connectionId, datagramDataLen);
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
     * 2. Server responds: Initial (ServerHello) в†ђ this method
     * 3. Client sends: Handshake (Finished) в†ђ handled by processHandshakePacket()
     * 4. Server responds: Handshake + 1-RTT (Certificate/Finished + HANDSHAKE_DONE)
     *
     * @param datagram The received datagram buffer containing Initial packet
     * @param ecnFlags
     */
    void processInitialAndRespond(PoolBuffer datagram, int ecnFlags) {
        if (state.get() == State.CLOSING || state.get() == State.CLOSED) {
            logger.warn("Connection is closing, no incoming packets processed");
            datagram.buf().position(datagram.buf().limit());
            return;
        }

        logger.debug("Processing Initial packet for CID: {} in state: {}", connectionId, state);

        // Step 1: Process Initial packet
        PoolBuffer frames = processInitialPacket(datagram, ecnFlags);

        boolean needAck = false;

        while (frames != null && frames.buf().hasRemaining()) {
            byte frameType = frames.buf().get();

            if (frameType == 0x02 || frameType == 0x03) { // ACK or ACK_ECN
                logger.debug("Received Initial ACK for CID: {}", connectionId);
                processAckFrame(frames.buf(), initialSpace, frameType); // ACK for Initial packets
            } else if (frameType == 0x00) { // PADDING
                // Skip padding
            } else if (frameType == 0x01) { // PING
                logger.debug("Received Initial PING for CID: {}", connectionId);
                needAck = true;
                updateTimeout();
            } else if (frameType == 0x06) { // CRYPTO
                needAck = true;

                long offset = QuicVarint.read(frames.buf());
                long length = QuicVarint.read(frames.buf());

                logger.info("Received Initial CRYPTO frame for CID: {}, offset={}, length={}",
                        connectionId, offset, length);

                if(state.get() != INITIAL) {
                    frames.buf().position(Math.min(frames.buf().limit(), frames.buf().position() + (int) length));
                    logger.info("State is {}, skipping crypto frame.", state);
                } else {
                    try {
                        rebuildCryptoFrame(offset, length, frames, this::extractTlsMeta);
                    } catch (IllegalStateException | IllegalArgumentException e) {
                        setState(State.CLOSING);
                        sendConnectionCloseAndUpdateState(QuicTransportError.PROTOCOL_VIOLATION.code(), "malformed crypto frame", false);
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

        logger.debug("Initial packet processed for connection {}", connectionId);

        if (state.get() == INITIAL && connectionMetadata.clientMetadata != null) {
            try {
                logger.info("Connection CID: {} got complete ClientHello, proceeding with handshake...", connectionId);

                if (connectionMetadata.clientMetadata.availableVersions.contains(QuicVersion.QUIC_VERSION_2.val)
                        && quicVersion != QuicVersion.QUIC_VERSION_2) {
                    quicVersion = QuicVersion.QUIC_VERSION_2;
                    connectionMetadata.initializeKeys(quicVersion, connectionMetadata.originalDCid);
                }

                sendInitialResponse();

                connectionMetadata.generateHandshakeSecrets(quicVersion);

                // Generate Handshake response with server Certificate/Finished.
                // This updates the transcript with: Certificate, CertificateVerify, server Finished.
                // Transition to HANDSHAKE state
                setState(State.HANDSHAKE);

                sendHandshakePacket();

            } catch (Exception e) {
                logger.error("Failed to send Handshake response", e);
            }
        }

        if (needAck) {
            sendInitialAck();
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
            QuicCrypto.processClientHello(connectionMetadata, frame);

            // Extract ALPN from TLS metadata
            if (connectionMetadata.clientMetadata.alpn != null) {
                this.negotiatedProtocol = connectionMetadata.clientMetadata.alpn;
                QuicApplicationProtocol protocol = QuicEngine.getStreamEngine().getProtocol(negotiatedProtocol);
                if (protocol != null) {
                    connectionMetadata.serverInitialLimits.maxData = protocol.getMaxData();
                    connectionMetadata.serverInitialLimits.maxBidi = protocol.getMaxBidirectionalStreamsPerConnection();
                    connectionMetadata.serverInitialLimits.maxUni = protocol.getMaxUnidirectionalStreamsPerConnection();
                    connectionMetadata.serverInitialLimits.maxStreamDataUni = protocol.getMaxStreamData();
                    connectionMetadata.serverInitialLimits.maxStreamDataBidiLocal = protocol.getMaxStreamData();
                    connectionMetadata.serverInitialLimits.maxStreamDataBidiRemote = protocol.getMaxStreamData();
                }
                logger.info("ALPN negotiated: {} for CID: {}", connectionMetadata.clientMetadata.alpn, connectionId);
            } else {
                logger.warn("No ALPN negotiated for CID: {}", connectionId);
            }

            logger.debug("TLS keys derived, cipher: {}", connectionMetadata.clientMetadata.selectedCipherSuite);
        }  catch (QuicException e) {
            if (e.getDemandedGroupId() != null) {
                logger.warn("ClientHello does not contain Key for supported KPG algorithms. Requesting another one {}", e.getDemandedGroupId());

                connectionMetadata.clientMetadata = null;
                sendHelloRetryRequest(e.getDemandedGroupId());
                return;
            }

            // RFC 9000 Section 10.2.3: Send CONNECTION_CLOSE with CRYPTO_ERROR
            // Error code = 0x0100 + TLS alert value (using handshake_failure = 40)
            logger.debug("Failed to process ClientHello for CID: {}, sending CONNECTION_CLOSE", connectionId, e);
            sendConnectionCloseAndUpdateState(e.getError() == null ? QuicTransportError.PROTOCOL_VIOLATION.code()
                : e.getError().code(),
            "ClientHello validation failed", false);
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
            PoolBuffer byteBuffer = getBufferPool().requestWriteBuffer();
            QuicFrameBuilder.writeConnectionCloseFrame(byteBuffer.buf(), errorCode, reason);

            logger.debug("Sending CONNECTION_CLOSE packet");
            if (ext) {
                TriStateQueue<ApplicationData> applicationDataTriStateQueue = new TriStateQueue<>(ApplicationData.EMPTY, ApplicationData.PROCESSED);
                applicationDataTriStateQueue.put(new ApplicationData(this, null, StreamManager.SERVICE_DATA, byteBuffer), 0, 0);
                wakeQueue.offer(applicationDataTriStateQueue);
            } else {
                sendPacket(byteBuffer, phase, false);
            }
            logger.warn("Sent CONNECTION_CLOSE for CID: {}, transitioning to CLOSING", connectionId);
        } catch (Exception encryptEx) {
            logger.error("Failed to encrypt CONNECTION_CLOSE packet", encryptEx);
            setState(State.CLOSED);
        }
    }

    private void sendHelloRetryRequest(short prefferedGroupId) {
        PoolBuffer hrrFrame = getBufferPool().requestWriteBuffer();

        writeHelloRetryRequest(hrrFrame.buf(), prefferedGroupId);
        QuicCrypto.applyHelloRetryRequestToTranscript(connectionMetadata, hrrFrame.buf());

        logger.debug("Sending HelloRetryRequest Initial packet");
        sendInitialPacket(hrrFrame);
    }

    private void sendPacket(PoolBuffer payload, PacketNumberSpace.PacketPhase phase, boolean retrasmit) {
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
                        quicVersion,
                        getBufferPool(),
                        clientCid,      // DCID = connection ID
                        connectionIdBytes,      // SCID = connection ID (server uses same)
                        packetNumber,
                        space.getLargestAckedPacketNumber(),
                        payload.buf().duplicate(),            // Plaintext payload
                        connectionMetadata.serverInitialCrypto.get(quicVersion)
                    );
                case HANDSHAKE -> QuicPacketBuilder.buildHandshakePacket(
                        quicVersion,
                        getBufferPool(),
                        clientCid,      // DCID = connection ID
                        connectionIdBytes,      // SCID = connection ID (server uses same)
                        packetNumber,
                        space.getLargestAckedPacketNumber(),
                        payload.buf().duplicate(),            // Plaintext payload
                        connectionMetadata.serverHandshakeCrypto
                    );
                case APPLICATION ->  QuicPacketBuilder.build1RttPacket(
                        quicVersion,
                        getBufferPool(),
                        clientCid,
                        packetNumber,
                        space.getLargestAckedPacketNumber(),
                        payload.buf().duplicate(),          // Plaintext payload
                        connectionMetadata.serverApplicationCrypto,
                        connectionMetadata.currentPhase
                );
            };
        } catch (QuicException e) {
            logger.error("Failed to build Initial packet", e);
            return;
        }

        logger.debug("Sending connection {} {} packet {}: {}b payload", connectionId, phase, packetNumber, payload.buf().remaining());

        // Track sent packet: store UNENCRYPTED payload for retransmission
        space.onPacketSent(currentTimestamp, packetNumber, payload, true);

        outboundQueue.add(new OutboundPacket(retrasmit ? PacketSource.RETRANSMISSION : PacketSource.NEW, completePacket, (congestionControl != null) ? congestionControl.getEctMarking() : ECT.ECT_0));
    }

    private void sendInitialPacket(PoolBuffer payload) {
        if (state.get() == INITIAL)
            sendPacket(payload, PacketNumberSpace.PacketPhase.INITIAL, false);
        else {
            logger.error("!!!Send initial packet in {} state", state.get());
            payload.release();
        }
    }
    private void sendHandshakePacket(PoolBuffer payload) {
        if (state.get() == HANDSHAKE)
            sendPacket(payload, PacketNumberSpace.PacketPhase.HANDSHAKE, false);
        else {
            logger.error("!!!Send handshake packet in {} state", state.get());
            payload.release();
        }
    }
    private void sendApplicationPacket(PoolBuffer payload) {
        if (state.get() == ESTABLISHED)
            sendPacket(payload, PacketNumberSpace.PacketPhase.APPLICATION, false);
        else {
            logger.error("!!!Send application packet in {} state", state.get());
            payload.release();
        }
    }

    /**
     * Creates Initial packet with ServerHello.
     */
    private void sendInitialResponse() throws IOException {
        // Create ServerHello uses the server's ephemeral public key already stored in tlsMetadata

        ChunkedOutputStreamWithAmendments outs = ChunkedOutputStreamWithAmendments.createNonWrapping(getBufferPool(),
                (int) (connectionMetadata.clientMetadata.maxUdpPayloadSize - CRYPTO_FRAME_MAX_HEADER_LENGTH - GCM_TAG_LENGTH - MAX_LONG_HEADER_LENGTH),
                GCM_TAG_LENGTH,
                (buffer, offset, _) -> {
                    QuicFrameBuilder.prependCryptoFrameHeader(offset, buffer);
                    return buffer.duplicate();
                }
        );
        TranscryptHashSupport transcryptHashSupport = new TranscryptHashSupport(outs, this::updateTranscript);

        transcryptHashSupport.startHashMessage("ServerHello");
        writeServerHello(outs, connectionMetadata);

        outs.flush();
        transcryptHashSupport.finish();

        PoolBuffer chunk;
        while ((chunk = outs.pollReadyChunk()) != null) {
            sendInitialPacket(chunk);
            logger.debug("Sending ServerHello Initial packet");
        }
        outs.close();
    }

    /**
     * Creates Handshake packet with EncryptedExtensions, Certificate, CertificateVerify, Finished.
     *
     * <p>TLS 1.3 server flight order (RFC 8446 В§4.4):
     * EncryptedExtensions -> Certificate -> CertificateVerify -> Finished
     * <p>
     * Each message is fed into the running transcript hash immediately after it is built,
     * so that CertificateVerify signs over EE+Cert and Finished covers the full flight.
     */
    private void sendHandshakePacket() throws Exception {
        ChunkedOutputStreamWithAmendments out = ChunkedOutputStreamWithAmendments.createNonWrapping(getBufferPool(),
                (int) connectionMetadata.clientMetadata.maxUdpPayloadSize - GCM_TAG_LENGTH - MAX_LONG_HEADER_LENGTH,
                GCM_TAG_LENGTH,
                (buffer, offset, _) -> {
                    QuicFrameBuilder.prependCryptoFrameHeader(offset, buffer);
                    QuicFrameBuilder.prependPingFrame(buffer);
                    return buffer.duplicate();
                });

        TranscryptHashSupport transcryptUpdater = new TranscryptHashSupport(out, this::updateTranscript);
        // -- 1. EncryptedExtensions --------------------------------------------
        transcryptUpdater.startHashMessage("EncryptedExtensions");
        QuicCrypto.putEncryptedExtensions(connectionMetadata, connectionId, statelessResetToken, quicVersion, out);

        // --- 2. Certificate ---------------------------------------------------
        transcryptUpdater.startHashMessage("Certificate");
        QuicCrypto.putCertificate(out);

        // -- 3. CertificateVerify ----------------------------------------------
        // Transcript now covers EE + Cert; CertificateVerify signs over that hash.
        transcryptUpdater.startHashMessage("CertificateVerify");
        QuicCrypto.putCertificateVerify(connectionMetadata, out);

        // -- 4. Finished -------------------------------------------------------
        transcryptUpdater.startHashMessage("server Finished");
        QuicCrypto.createServerFinished(connectionMetadata, out);

        out.flush();
        transcryptUpdater.finish();

        PoolBuffer chunk;
        while ((chunk = out.pollReadyChunk()) != null) {
            sendHandshakePacket(chunk);
        }
        out.close();
    }

    /**
     * Feeds a TLS handshake message into the running transcript hash and logs it.
     * The buffer's position is not advanced (uses a duplicate for reading).
     */
    private void updateTranscript(ByteBuffer message, String messageName) {
        connectionMetadata.updateTranscript(message);
    }

    /**
     * Creates 1-RTT (Short Header) packet with HANDSHAKE_DONE frame.
     * This signals to the client that the handshake is complete.
     */
    private void sendHandshakeDonePacket() {
        // Create HANDSHAKE_DONE frame (type 0x1e)
        PoolBuffer frame = getBufferPool().requestWriteBuffer();
        int start = frame.buf().position();
        QuicFrameBuilder.writeHandshakeDoneFrame(frame.buf());
        frame.buf().put((byte) 0x01); // PING
        frame.buf().limit(frame.buf().position());
        frame.buf().position(start);

        logger.debug("Sending HANDSHAKE_DONE frame in 1-RTT packet");
        sendApplicationPacket(frame);
    }

    private void sendInitialAck() {
        PoolBuffer buffer = getBufferPool().requestWriteBuffer();
        QuicFrameBuilder.writeAckEcnFrame(initialSpace, currentTimestamp, buffer.buf());
        logger.debug("Sending ACK Initial packet");
        sendPacket(buffer, PacketNumberSpace.PacketPhase.INITIAL, false);
    }
    private void sendHandshakeAck() {
        PoolBuffer buffer = getBufferPool().requestWriteBuffer();
        QuicFrameBuilder.writeAckEcnFrame(handshakeSpace, currentTimestamp, buffer.buf());
        logger.debug("Sending Handshake ACK");
        sendPacket(buffer, PacketNumberSpace.PacketPhase.HANDSHAKE, false);
    }
    private void send1RttAck() {
        PoolBuffer buffer = getBufferPool().requestWriteBuffer();
        QuicFrameBuilder.writeAckEcnFrame(applicationSpace, currentTimestamp, buffer.buf());
        logger.debug("Sending 1-RTT ACK");
        sendPacket(buffer, PacketNumberSpace.PacketPhase.APPLICATION, false);
    }

    /**
     * Processes ACK frame and updates packet number space.
     * RFC 9000 Section 19.3: ACK Frame Format
     */
    private void processAckFrame(ByteBuffer buffer, PacketNumberSpace space, byte frameType) {
        long largestAcked = QuicVarint.read(buffer);
        long ackDelayExponent = space.phase == PacketNumberSpace.PacketPhase.INITIAL ? 3 : connectionMetadata.clientMetadata.ackDelayExponent;
        long ackDelay = QuicVarint.read(buffer) << ackDelayExponent;
        long rangeCount = QuicVarint.read(buffer);
        long firstRange = QuicVarint.read(buffer);

        if (rangeCount > 256) { //skip
            logger.error("Range count too high {}", rangeCount);
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

            if (i < 256) {
                long rangeLargest = currentSmallest - gap - 2;
                long rangeSmallest = rangeLargest - rangeLength;
                if (rangeSmallest < 0 || rangeLargest > 65535) {
                    continue;
                }

                ackRanges.add(new PacketNumberSpace.AckRange(rangeSmallest, rangeLargest));

                currentSmallest = rangeSmallest;
            }
        }

        long ceCounter = 0;
        if (frameType == 0x03) {
            QuicVarint.read(buffer); // 1. ECT(0) Packets
            QuicVarint.read(buffer); // 2. ECT(1) Packets
            ceCounter = QuicVarint.read(buffer); // 3. Congestion Experienced Packets
        }

        boolean needRetansmit = (space.getLargestAckedPacketNumber() < largestAcked);

        space.onAckReceived(currentTimestamp, largestAcked, ackRanges, ackDelay, connectionStreamManager, ceCounter);

        if (needRetansmit) retransmitLostPackets(space);
    }

    public void retransmitLostPackets() {
        if (connectionMetadata.serverInitialCrypto != null) retransmitLostPackets(initialSpace);
        if (connectionMetadata.serverHandshakeCrypto != null) retransmitLostPackets(handshakeSpace);
        if (connectionMetadata.serverApplicationCrypto != null) retransmitLostPackets(applicationSpace);
    }

    private void retransmitLostPackets(PacketNumberSpace space) {
        Map<Long, PacketNumberSpace.SentPacket> lostPackets = space.detectLostPackets(currentTimestamp);

        // Re-wrap lost packets with NEW packet numbers and encryption
        if (!lostPackets.isEmpty()) {
            logger.warn("Detected {} lost packets in connection {}, retransmitting with NEW packet numbers", lostPackets.size(), connectionId);

            for (Map.Entry<Long, PacketNumberSpace.SentPacket> entry : lostPackets.entrySet()) {
                long originalPn = entry.getKey();
                PacketNumberSpace.SentPacket sentPacket = entry.getValue();

                // Allocate a BRAND NEW packet number for retransmission
                logger.info("Retransmitting lost packet {} as new packet (phase: {})",
                        originalPn, sentPacket.packetPhase);

                sendPacket(sentPacket.unencryptedPayload, sentPacket.packetPhase, true);
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

        // RFC 9000: Transition to CLOSING if not already closing
        if (state.get() != State.CLOSED && state.get() != State.CLOSING) {
            setState(State.CLOSING);
        }

        if (frameType == 0x1c) {
            logger.warn("CONNECTION_CLOSE cid {} (QUIC): error_code={}, frame_type={}, reason=\"{}\"",
                    connectionId, errorCode, triggeringFrameType, reason);
        } else {
            logger.warn("CONNECTION_CLOSE cid {} (Application): error_code={}, reason=\"{}\"",
                    connectionId, errorCode, reason);
        }
    }

    /**
     * Sends a Stateless Reset packet as per RFC 9000 Section 10.3.
     * A Stateless Reset is indistinguishable from a regular packet with a short header,
     * containing random bytes and a 16-byte Stateless Reset Token at the higher.
     *
     * @param incomingPacketSize Size of the incoming packet (used to determine reset size)
     */
    private void sendStatelessReset(int incomingPacketSize) {
        try {
            PoolBuffer frame = QuicPacketBuilder.writeStatelessResetFrame(getBufferPool(), incomingPacketSize, statelessResetToken);
            sendInitialPacket(frame);
            logger.info("Sent Stateless Reset ({} bytes)", frame.buf().remaining());
        } catch (Exception e) {
            logger.error("Failed to send Stateless Reset", e);
        }
    }
}

