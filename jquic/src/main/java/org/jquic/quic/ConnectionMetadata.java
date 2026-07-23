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

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

/**
 * TLS metadata associated with a QUIC connection.
 *
 * <p>Acts as the running state object across the entire TLS 1.3 key schedule
 * (RFC 8446 Section 7). It is created first вЂ” before any crypto вЂ” and then
 * populated gradually as the handshake progresses:
 * <ol>
 *   <li>Constructed with the Early Secret.</li>
 *   <li>Stage 1 ({@link QuicCrypto#processClientHello}): Handshake secrets,
 *       ALPN, randoms, and HP keys are set.</li>
 *   <li>Stage 2 ({@link QuicCrypto#createApplicationKeys}): 1-RTT secrets
 *       are derived once the full transcript is available.</li>
 * </ol>
 *
 * <p>A running SHA-256 transcript hash is maintained by calling
 * {@link #updateTranscript(byte[])} with each TLS handshake message in wire order:
 * ClientHello в†’ ServerHello в†’ EncryptedExtensions в†’ Certificate в†’
 * CertificateVerify в†’ (server) Finished в†’ (client) Finished.
 * Snapshot the current hash at any time via {@link #transcriptHash()}.
 */
public class ConnectionMetadata {
    // ---- Set at construction (always present) ----
    /**
     * Early Secret = HKDF-Extract(salt=0, IKM=0) without PSK.
     * Retained so future PSK support only needs to change the derivation here.
     */
    public byte[] earlySecret;

    /**
     * Running SHA-256 digest of handshake messages in wire order.
     */
    private final java.security.MessageDigest transcriptDigest;

    // ---- Set during stage 1 (processClientHello) ----

    public byte[] originalDCid;
    public long negotiatedIdleTimeoutMs;

    /**
     * Handshake secret bytes retained for Master Secret derivation in stage 2.
     */
    byte[] handshakeSecretBytes;

    public QuicCrypto.PacketProtectionKeysWithHP clientInitialKeys;
    public QuicCrypto.PacketProtectionKeysWithHP serverInitialKeys;
    public QuicCrypto.PacketProtectionKeysWithHP clientHandshakeKeys;
    public byte[] clientHandshakeTrafficSecret;
    public QuicCrypto.PacketProtectionKeysWithHP serverHandshakeKeys;
    public byte[] serverHandshakeTrafficSecret;
    public QuicCrypto.PacketProtectionKeys clientApplicationKeys;
    public QuicCrypto.PacketProtectionKeys serverApplicationKeys;
    public QuicCrypto.PacketProtectionKeys prevClientApplicationKeys;
    public QuicCrypto.PacketProtectionKeys prevServerApplicationKeys;
    public byte[] clientApplicationTrafficSecret;
    public byte[] serverApplicationTrafficSecret;
    public Cipher clientApplicationHeaderProtection;
    public Cipher serverApplicationHeaderProtection;

    public byte currentPhase;
    public long lastPhaseSwitchPacketNumber = -1;

    public ClientMetadataNegotiated clientMetadata;
    public InitialStreamLimits serverInitialStreamLimits = new InitialStreamLimits();
    /**
     * Server's ephemeral public key bytes (32 bytes).
     * Set during stage 1; included in the ServerHello key_share extension.
     */
    public byte[] serverEphemeralPublicKey;
    public short selectedKeyScheme;

    /**
     * Selected signature algorithm
     */
    public Short selectedSignatureScheme;

    /**
     * Creates a fresh {@code TlsMetadata} seeded with the Early Secret.
     * All other fields are set by the processing methods as the handshake progresses.
     */
    public ConnectionMetadata() {
        try {
            this.transcriptDigest = java.security.MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * Feeds raw TLS handshake message bytes into the running transcript hash.
     * Must be called in wire order:
     * ClientHello в†’ ServerHello в†’ EncryptedExtensions в†’ Certificate в†’
     * CertificateVerify в†’ (server) Finished в†’ (client) Finished.
     *
     * @param message raw TLS handshake message bytes (including 4-byte header:
     *                msg_type + 3-byte length)
     */
    public synchronized void updateTranscript(ByteBuffer message) {
        message.mark();
        transcriptDigest.update(message);
        message.reset();
    }

    public synchronized void updateTranscript(byte[] message) {
        transcriptDigest.update(message);
    }

    /**
     * Resets the running transcript digest to its initial (empty) state.
     *
     * <p>Used during HelloRetryRequest processing (RFC 8446 В§4.4.1): after sending
     * an HRR the transcript must be replaced with a synthetic {@code message_hash}
     * record followed by the HRR itself. Call this method, then feed the synthetic
     * record and the HRR via {@link #updateTranscript}.
     */
    public synchronized void resetTranscript() {
        transcriptDigest.reset();
    }

    /**
     * Returns a non-destructive snapshot of the current transcript hash.
     *
     * @return 32-byte SHA-256 digest of all messages fed so far
     */
    public synchronized byte[] transcriptHash() {
        try {
            return ((java.security.MessageDigest) transcriptDigest.clone()).digest();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("MessageDigest.clone() not supported", e);
        }
    }

    /**
     * Sets the 1-RTT application keys.
     * Called by {@link QuicCrypto#createApplicationKeys} once the transcript is complete.
     */
    void setApplicationKeys(QuicCrypto.PacketProtectionKeys clientApplicationKeys, QuicCrypto.PacketProtectionKeys serverApplicationKeys) {
        this.clientApplicationKeys = clientApplicationKeys;
        this.serverApplicationKeys = serverApplicationKeys;
    }

    public static class InitialStreamLimits {
        public Integer maxBidi = 128;  // Maximum number if bidirectional streams we are ready to accept from the start
        public Integer maxUni = 128;  // Maximum number if unidirectional streams we are ready to accept from the start
        public Integer maxStreamDataUni = 1048576; // Maximum data per unidirectional stream we are ready to accept from it initially
        public Integer maxStreamDataBidiLocal = 1048576; // Maximum data per bidirectional stream (opened by us) we are ready to accept from it initially
        public Integer maxStreamDataBidiRemote = 1048576; // Maximum data per bidirectional stream (opened by peer) we are ready to accept from it initially
        public Integer maxData = 1048576; // Total maximum data per connection we are ready to accept from the start
    }

    /**
     * All data extracted from a ClientHello message.
     */
    public static class ClientMetadataNegotiated {
        /** Negotiated ALPN protocol (e.g. "h3"), or null if not provided. */
        public final String alpn;
        /** max_idle_timeout from QUIC transport parameters (0 if absent). */
        public final long maxIdleTimeoutMs;
        public final long maxUdpPayloadSize;
        public final InitialStreamLimits initialStreamLimits = new InitialStreamLimits();
        public final long ackDelayExponent;
        public final long activeConnectionIdLimit;
        public final List<Short> supportedSignatures;
        public final List<Short> supportedGroups;
        public final Map<Short, byte[]> clientKeys;
        public final String selectedCipherSuite = QuicCrypto.CIPHER_SUITE;

        public ClientMetadataNegotiated(String alpn, long maxIdleTimeoutMs, List<Short> supportedGroups, Map<Short, byte[]> clientKeys, long maxUdpPayloadSize, long initialMaxData, long initialMaxStreamDataBidiLocal, long initialMaxStreamDataBidiRemote, long initialMaxStreamDataUni, long initialMaxStreamsBidi, long initialMaxStreamsUni, List<Short> supportedSignatures, long ackDelayExponent, long activeConnectionIdLimit) {
            this.alpn = alpn;
            this.maxIdleTimeoutMs = maxIdleTimeoutMs;
            this.maxUdpPayloadSize = maxUdpPayloadSize;
            this.initialStreamLimits.maxData = (int)initialMaxData;
            this.initialStreamLimits.maxStreamDataBidiLocal = (int)initialMaxStreamDataBidiLocal;
            this.initialStreamLimits.maxStreamDataBidiRemote = (int)initialMaxStreamDataBidiRemote;
            this.initialStreamLimits.maxStreamDataUni = (int)initialMaxStreamDataUni;
            this.initialStreamLimits.maxBidi = (int)initialMaxStreamsBidi;
            this.initialStreamLimits.maxUni = (int)initialMaxStreamsUni;
            this.supportedSignatures = supportedSignatures;
            this.supportedGroups = supportedGroups;
            this.ackDelayExponent = ackDelayExponent;
            this.activeConnectionIdLimit = activeConnectionIdLimit;
            this.clientKeys = clientKeys;
        }
    }
}

