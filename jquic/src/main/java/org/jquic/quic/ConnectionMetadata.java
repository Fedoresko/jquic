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

import org.jquic.quic.crypto.NativeCrypto;
import org.jquic.quic.crypto.QuicCrypto;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;

/**
 * TLS metadata associated with a QUIC connection.
 *
 * <p>Acts as the running state object across the entire TLS 1.3 key schedule
 * (RFC 8446 Section 7). It is created first - before any crypto - and then
 * populated gradually as the handshake progresses:
 * <ol>
 *   <li>Constructed with the Early Secret.</li>
 *   <li>Stage 1 ({@link QuicCrypto#processClientHello}): Handshake secrets,
 *       ALPN, randoms, and HP keys are set.</li>
 *   <li>Stage 2 ({@link ConnectionMetadata#createApplicationKeys}): 1-RTT secrets
 *       are derived once the full transcript is available.</li>
 * </ol>
 *
 * <p>A running SHA-256 transcript hash is maintained by calling
 * {@link #updateTranscript(byte[])} with each TLS handshake message in wire order:
 * ClientHello -> ServerHello -> EncryptedExtensions -> Certificate ->
 * CertificateVerify -> (server) Finished -> (client) Finished.
 * Snapshot the current hash at any time via {@link #transcriptHash()}.
 */
public class ConnectionMetadata {
    // ---- Set at construction (always present) ----

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
    public byte[] handshakeSecretBytes;

    public NativeCrypto clientInitialCrypto;
    public NativeCrypto serverInitialCrypto;
    public NativeCrypto clientHandshakeCrypto;
    public NativeCrypto serverHandshakeCrypto;
    public byte[] clientHandshakeTrafficSecret;

    public byte[] serverHandshakeTrafficSecret;
    public NativeCrypto clientApplicationCrypto;
    public NativeCrypto serverApplicationCrypto;
    public NativeCrypto prevClientApplicationCrypto;
    public NativeCrypto prevServerApplicationCrypto;
    public byte[] clientApplicationTrafficSecret;
    public byte[] serverApplicationTrafficSecret;

    public byte currentPhase;
    public long lastPhaseSwitchPacketNumber = -1;

    public ClientMetadataNegotiated clientMetadata;
    public InitialStreamLimits serverInitialLimits = new InitialStreamLimits();
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
    private static final Logger logger =  LoggerFactory.getLogger(ConnectionMetadata.class);

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

    private static byte[] getQuicInitialSalt(QuicVersion version) throws QuicCrypto.CryptoException {
        return switch (version) {
            case QUIC_VERSION_1 -> QuicCrypto.QUIC_VERSION_1_SALT;
            case QUIC_VERSION_2 -> QuicCrypto.QUIC_VERSION_2_SALT;
            case UNKNOWN -> throw new QuicCrypto.CryptoException("Unsupported Vesrion");

        };
    }

    private static ByteBuffer wrapDirect(byte[] data) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(data.length);
        buffer.put(data);
        return buffer.flip();
    }

    /**
     * Derives Initial packet protection keys from destination connection ID.
     * Does not decrypt - only derives keys for header protection removal.
     */
    public static QuicCrypto.PacketProtectionKeysWithHP[] deriveInitialKeys(QuicVersion quicVersion, byte[] destinationCid) throws QuicCrypto.CryptoException {
        try {
            // Derive Initial secrets using HKDF with DCID
            byte[] initialSecret = QuicCrypto.hkdfExtract( getQuicInitialSalt(quicVersion) , destinationCid);

            // Derive client keys
            byte[] clientInitialSecret = QuicCrypto.hkdfExpandLabel(initialSecret, "client in", new byte[0], 32);
            SecretKey clientKey = QuicCrypto.deriveKey(quicVersion, clientInitialSecret);
            byte[] clientIv = QuicCrypto.deriveIv(quicVersion, clientInitialSecret);
            byte[] clientHp = QuicCrypto.deriveHp(quicVersion, clientInitialSecret);

            // Derive server keys
            byte[] serverInitialSecret = QuicCrypto.hkdfExpandLabel(initialSecret, "server in", new byte[0], 32);
            SecretKey serverKey = QuicCrypto.deriveKey(quicVersion, serverInitialSecret);
            byte[] serverIv = QuicCrypto.deriveIv(quicVersion, serverInitialSecret);
            byte[] serverHp = QuicCrypto.deriveHp(quicVersion, serverInitialSecret);


            ByteBuffer clientKeySeg = wrapDirect(clientKey.getEncoded());
            ByteBuffer serverKeySeg = wrapDirect(serverKey.getEncoded());

            ByteBuffer clientHpKeySeg = wrapDirect(clientHp);
            ByteBuffer serverHpKeySeg = wrapDirect(serverHp);

            QuicCrypto.PacketProtectionKeysWithHP clientKeys = new QuicCrypto.PacketProtectionKeysWithHP(clientKeySeg, clientIv, clientHpKeySeg);
            QuicCrypto.PacketProtectionKeysWithHP serverKeys = new QuicCrypto.PacketProtectionKeysWithHP(serverKeySeg, serverIv, serverHpKeySeg);

            return new QuicCrypto.PacketProtectionKeysWithHP[] { clientKeys, serverKeys };

        } catch (GeneralSecurityException e) {
            throw new QuicCrypto.CryptoException("Failed to derive Initial keys", e);
        }
    }

    public void generateHandshakeSecrets(QuicVersion quicVersion) throws QuicCrypto.CryptoException {
        // Context = transcript hash up to and including ClientHello.
        // ServerHello is appended later by createInitialResponse.
        byte[] transcriptSoFar = transcriptHash();
        byte[] clientHandshakeTrafficSecret = QuicCrypto.hkdfExpandLabel(
                handshakeSecretBytes, "c hs traffic", transcriptSoFar, 32);
        byte[] serverHandshakeTrafficSecret = QuicCrypto.hkdfExpandLabel(
                handshakeSecretBytes, "s hs traffic", transcriptSoFar, 32);

        this.serverHandshakeTrafficSecret = serverHandshakeTrafficSecret;
        this.clientHandshakeTrafficSecret = clientHandshakeTrafficSecret;

        byte[] serverHp = QuicCrypto.deriveHp(quicVersion, serverHandshakeTrafficSecret);
        SecretKey serverKey = QuicCrypto.deriveKey(quicVersion, serverHandshakeTrafficSecret);
        ByteBuffer serverKeySeg = wrapDirect(serverKey.getEncoded());
        ByteBuffer serverHpKeySeg = wrapDirect(serverHp);

        serverHandshakeCrypto = new NativeCrypto(new QuicCrypto.PacketProtectionKeysWithHP(serverKeySeg,
                QuicCrypto.deriveIv(quicVersion, serverHandshakeTrafficSecret), serverHpKeySeg));

        byte[] clientHp = QuicCrypto.deriveHp(quicVersion, clientHandshakeTrafficSecret);
        ByteBuffer clientHpKeySeg = wrapDirect(clientHp);
        SecretKey clientKey = QuicCrypto.deriveKey(quicVersion, clientHandshakeTrafficSecret);
        ByteBuffer clientKeySeg = wrapDirect(clientKey.getEncoded());

        clientHandshakeCrypto = new NativeCrypto(new QuicCrypto.PacketProtectionKeysWithHP(clientKeySeg,
                QuicCrypto.deriveIv(quicVersion, clientHandshakeTrafficSecret), clientHpKeySeg));
    }

    /**
     * Stage 2 of the TLS 1.3 key schedule: derives the Master Secret and
     * 1-RTT (application) traffic secrets once the handshake transcript is complete.
     *
     * <p>The transcript hash is taken directly from {@link ConnectionMetadata#transcriptHash()},
     * which must have been updated with all messages up to and including the client
     * Finished before this method is called.
     *
     * @throws QuicCrypto.CryptoException if key derivation fails
     */
    public void createApplicationKeys(QuicVersion quicVersion) throws QuicCrypto.CryptoException {
        try {
            // Master Secret = HKDF-Extract(Derive-Secret(Handshake Secret, "derived", ""), 0)
            byte[] derivedFromHandshake = QuicCrypto.hkdfExpandLabel(
                    handshakeSecretBytes, "derived", QuicCrypto.sha256(new byte[0]), 32);
            byte[] masterSecret = QuicCrypto.hkdfExtract(derivedFromHandshake, new byte[32]);

            // Snapshot the current transcript hash (all messages up to client Finished)
            byte[] context = transcriptHash();

            clientApplicationTrafficSecret = QuicCrypto.hkdfExpandLabel(
                    masterSecret, "c ap traffic", context, 32);

            serverApplicationTrafficSecret = QuicCrypto.hkdfExpandLabel(
                    masterSecret, "s ap traffic", context, 32);

            SecretKey clientApplicationSecret = QuicCrypto.deriveKey(quicVersion, clientApplicationTrafficSecret);
            SecretKey serverApplicationSecret = QuicCrypto.deriveKey(quicVersion, serverApplicationTrafficSecret);
            byte[] clientApplicationHpKey = QuicCrypto.deriveHp(quicVersion, clientApplicationTrafficSecret);
            byte[] serverApplicationHpKey = QuicCrypto.deriveHp(quicVersion, serverApplicationTrafficSecret);
            byte[] clientApplicationIv = QuicCrypto.deriveIv(quicVersion, clientApplicationTrafficSecret);
            byte[] serverApplicationIv = QuicCrypto.deriveIv(quicVersion, serverApplicationTrafficSecret);

            ByteBuffer clientHpKeySeg = wrapDirect(clientApplicationHpKey);
            ByteBuffer serverHpKeySeg = wrapDirect(serverApplicationHpKey);

            ByteBuffer clientKeySeg = wrapDirect(clientApplicationSecret.getEncoded());
            ByteBuffer serverKeySeg = wrapDirect(serverApplicationSecret.getEncoded());

            clientApplicationCrypto = new NativeCrypto(new QuicCrypto.PacketProtectionKeysWithHP(clientKeySeg, clientApplicationIv, clientHpKeySeg));
            serverApplicationCrypto = new NativeCrypto(new QuicCrypto.PacketProtectionKeysWithHP(serverKeySeg, serverApplicationIv, serverHpKeySeg));

            logger.debug("Derived 1-RTT application keys from transcript hash (stage 2 complete)");
        } catch (GeneralSecurityException e) {
            throw new QuicCrypto.CryptoException("Failed to derive application keys", e);
        }
    }

    public void rotateApplicationKeys(QuicVersion quicVersion) throws Exception {
        try {
            if (prevClientApplicationCrypto != null) {
                prevClientApplicationCrypto.close();
                prevServerApplicationCrypto.close();
            }
            prevClientApplicationCrypto = clientApplicationCrypto;
            prevServerApplicationCrypto = serverApplicationCrypto;

            clientApplicationTrafficSecret = QuicCrypto.hkdfExpandLabel(
                    clientApplicationTrafficSecret, QuicCrypto.kuLabel(quicVersion), new byte[0], 32);
            serverApplicationTrafficSecret = QuicCrypto.hkdfExpandLabel(
                    serverApplicationTrafficSecret, QuicCrypto.kuLabel(quicVersion), new byte[0], 32);

            SecretKey clientKey = QuicCrypto.deriveKey(quicVersion, clientApplicationTrafficSecret);
            SecretKey serverKey = QuicCrypto.deriveKey(quicVersion, serverApplicationTrafficSecret);

            ByteBuffer clientKeySeg = wrapDirect(clientKey.getEncoded());
            ByteBuffer serverKeySeg = wrapDirect(serverKey.getEncoded());

            clientApplicationCrypto = new NativeCrypto(new QuicCrypto.PacketProtectionKeysWithHP(clientKeySeg,
                    QuicCrypto.deriveIv(quicVersion, clientApplicationTrafficSecret),
                    prevClientApplicationCrypto.getHpKey()));

            serverApplicationCrypto = new NativeCrypto(new QuicCrypto.PacketProtectionKeysWithHP(serverKeySeg,
                    QuicCrypto.deriveIv(quicVersion, serverApplicationTrafficSecret),
                    prevServerApplicationCrypto.getHpKey()));

            currentPhase = (byte)( (currentPhase == 0) ? 1 : 0 );

            logger.info("Rotated application keys, current Key Phase set to {}", currentPhase);
        } catch (GeneralSecurityException e) {
            throw new QuicCrypto.CryptoException("Failed to rotate application keys", e);
        }
    }

    public @Nullable Boolean initializeKeys(QuicVersion quicVersion, byte[] destinationCid) {
        boolean isNewConnection = false;
        if (clientInitialCrypto == null) {
            originalDCid = destinationCid;
            isNewConnection = true;
            try {
                QuicCrypto.PacketProtectionKeysWithHP[] keys = deriveInitialKeys(quicVersion,
                        destinationCid);
                clientInitialCrypto = new NativeCrypto(keys[0]);
                serverInitialCrypto = new NativeCrypto(keys[1]);
            } catch (QuicCrypto.CryptoException e) {
                // RFC 9000: Silently discard packets that fail key derivation
                logger.warn("Failed to derive Initial keys for CID: {}, discarding packet", destinationCid);
                return null;
            }
        }
        return isNewConnection;
    }

    /**
     * Feeds raw TLS handshake message bytes into the running transcript hash.
     * Must be called in wire order:
     * ClientHello -> ServerHello -> EncryptedExtensions -> Certificate ->
     * CertificateVerify -> (server) Finished -> (client) Finished.
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

    public static class InitialStreamLimits {
        public Integer maxBidi = 128;  // Maximum number if bidirectional streams we are ready to accept from the start
        public Integer maxUni = 128;  // Maximum number if unidirectional streams we are ready to accept from the start
        public Integer maxStreamDataUni = 1048576; // Maximum data per unidirectional stream we are ready to accept from it initially
        public Integer maxStreamDataBidiLocal = 1048576; // Maximum data per bidirectional stream (opened by us) we are ready to accept from it initially
        public Integer maxStreamDataBidiRemote = 1048576; // Maximum data per bidirectional stream (opened by peer) we are ready to accept from it initially
        public Integer maxData = 1048576; // Total maximum data per connection we are ready to accept from the start
        public long maxConnections = 100; // Total number of simultaneous connections from the client
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
        public final List<Short> supportedSignatures;
        public final List<Short> supportedGroups;
        public final Map<Short, byte[]> clientKeys;
        public final String selectedCipherSuite = QuicCrypto.CIPHER_SUITE;

        public ClientMetadataNegotiated(String alpn, long maxIdleTimeoutMs, List<Short> supportedGroups, Map<Short, byte[]> clientKeys, long maxUdpPayloadSize, long initialMaxData, long initialMaxStreamDataBidiLocal, long initialMaxStreamDataBidiRemote, long initialMaxStreamDataUni, long initialMaxStreamsBidi, long initialMaxStreamsUni, List<Short> supportedSignatures, long ackDelayExponent) {
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
            this.clientKeys = clientKeys;
        }
    }
}

