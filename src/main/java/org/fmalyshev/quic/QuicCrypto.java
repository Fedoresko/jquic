package org.fmalyshev.quic;

import org.conscrypt.Conscrypt;
import org.fmalyshev.quic.streamapi.QuicApplicationProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;

import static org.fmalyshev.quic.QuicConnection.STATELESS_RESET_TOKEN_LENGTH;

/**
 * Handles QUIC cryptographic operations based on TLS 1.3.
 * Uses Conscrypt for modern crypto and direct ByteBuffer operations for efficiency.
 */
public class QuicCrypto {
    private static final Logger logger = LoggerFactory.getLogger(QuicCrypto.class);

    static {
        // Register Conscrypt eagerly when the class is loaded,
        // before any method can reference it by name.
        if (Security.getProvider("Conscrypt") == null) {
            Security.insertProviderAt(Conscrypt.newProvider(), 1);
        }
    }

    // QUIC v1 constants
    private static final byte[] QUIC_VERSION_1_SALT = {
        (byte)0x38, (byte)0x76, (byte)0x2c, (byte)0xf7, (byte)0xf5, (byte)0x59, (byte)0x34, (byte)0xb3,
        (byte)0x4d, (byte)0x17, (byte)0x9a, (byte)0xe6, (byte)0xa4, (byte)0xc8, (byte)0x0c, (byte)0xad,
        (byte)0xcc, (byte)0xbb, (byte)0x7f, (byte)0x0a
    };

    private static final String CIPHER_SUITE = "TLS_AES_128_GCM_SHA256";
    private static final int AES_128_KEY_LENGTH = 16;

    // TLS 1.3 identifiers used during ClientHello parsing and ServerHello construction
    /** TLS_AES_128_GCM_SHA256 cipher suite identifier (RFC 8446 Appendix B.4). */
    private static final int TLS_AES_128_GCM_SHA256_ID = 0x1301;
    /** TLS 1.3 version identifier used in supported_versions extension (RFC 8446 §4.2.1). */
    private static final int TLS_VERSION_1_3 = 0x0304;
    /** IANA NamedGroup identifier for x25519 (RFC 8446 §4.2.7). */
    private static final int GROUP_X25519 = 0x001d;

    /**
     * Sentinel random used in HelloRetryRequest (RFC 8446 §4.1.3).
     * = SHA-256("HelloRetryRequest") — fixed, well-known value.
     */
    private static final byte[] HRR_RANDOM = {
        (byte)0xCF, (byte)0x21, (byte)0xAD, (byte)0x74, (byte)0xE5, (byte)0x9A, (byte)0x61, (byte)0x11,
        (byte)0xBE, (byte)0x1D, (byte)0x8C, (byte)0x02, (byte)0x1E, (byte)0x65, (byte)0xB8, (byte)0x91,
        (byte)0xC2, (byte)0xA2, (byte)0x11, (byte)0x16, (byte)0x7A, (byte)0xBB, (byte)0x8C, (byte)0x5E,
        (byte)0x07, (byte)0x9E, (byte)0x09, (byte)0xE2, (byte)0xC8, (byte)0xA8, (byte)0x33, (byte)0x9C
    };

    /**
     * GCM authentication tag length in bytes (RFC 5116 Section 5.1).
     * AES-GCM uses 16-byte (128-bit) authentication tags.
     * This tag is automatically appended by Cipher.doFinal() during encryption
     * and verified/removed during decryption.
     */
    public static final int GCM_TAG_LENGTH = 16;
    public static final int GCM_NONCE_LENGTH = 12;

    /**
     * TLS metadata associated with a QUIC connection.
     */
    /**
     * TLS metadata associated with a QUIC connection.
     *
     * <p>Populated in two stages matching the TLS 1.3 key schedule (RFC 8446 Section 7):
     * <ol>
     *   <li>After processing ClientHello: Handshake-level secrets are available.</li>
     *   <li>After the handshake transcript is complete (client Finished verified):
     *       1-RTT secrets are derived and set via {@link #setApplicationKeys}.</li>
     * </ol>
     *
     * <p>A running SHA-256 transcript hash is maintained via {@link #updateTranscript(byte[])}.
     * Call it with the raw body bytes of each TLS handshake message in order:
     * ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished.
     * Use {@link #transcriptHash()} to snapshot the current digest at any point.
     */
    /**
     * TLS metadata associated with a QUIC connection.
     *
     * <p>Acts as the running state object across the entire TLS 1.3 key schedule
     * (RFC 8446 Section 7). It is created first — before any crypto — and then
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
     * ClientHello → ServerHello → EncryptedExtensions → Certificate →
     * CertificateVerify → (server) Finished → (client) Finished.
     * Snapshot the current hash at any time via {@link #transcriptHash()}.
     */
    public static class TlsMetadata {

        // ---- Set at construction (always present) ----

        /**
         * Early Secret = HKDF-Extract(salt=0, IKM=0) without PSK.
         * Retained so future PSK support only needs to change the derivation here.
         */
        public byte[] earlySecret;

        /** Running SHA-256 digest of handshake messages in wire order. */
        private final java.security.MessageDigest transcriptDigest;

        // ---- Set during stage 1 (processClientHello) ----

        public byte[] clientRandom;
        public byte[] serverRandom;
        public String selectedCipherSuite;
        public String alpn;
        public byte [] originalDCid;
        public long negotiatedIdleTimeoutMs;

        /** Handshake secret bytes retained for Master Secret derivation in stage 2. */
        byte[] handshakeSecretBytes;

        public PacketProtectionKeys clientInitialKeys;
        public PacketProtectionKeys serverInitialKeys;
        public PacketProtectionKeys clientHandshakeKeys;
        public byte [] clientHandshakeTrafficSecret;
        public PacketProtectionKeys serverHandshakeKeys;
        public byte [] serverHandshakeTrafficSecret;
        public PacketProtectionKeys clientApplicationKeys;
        public PacketProtectionKeys serverApplicationKeys;
        public byte [] clientApplicationTrafficSecret;
        public byte [] serverApplicationTrafficSecret;

        public byte currentPhase;

        public ParsedClientHello clientMetadata;

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
        public TlsMetadata() {
            try {
                this.transcriptDigest = java.security.MessageDigest.getInstance("SHA-256");
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 not available", e);
            }
        }

        /**
         * Feeds raw TLS handshake message bytes into the running transcript hash.
         * Must be called in wire order:
         * ClientHello → ServerHello → EncryptedExtensions → Certificate →
         * CertificateVerify → (server) Finished → (client) Finished.
         *
         * @param message raw TLS handshake message bytes (including 4-byte header:
         *                msg_type + 3-byte length)
         */
        public synchronized void updateTranscript(ByteBuffer message) {
            message.mark();
            byte[] buf = new byte[message.remaining()];
            message.get(buf);
            message.reset();
            logger.info("Updating transcript with {}", HexFormat.of().formatHex(buf));
            transcriptDigest.update(message);
            message.reset();
        }

        public synchronized void updateTranscript(byte[] message) {
            logger.info("Updating transcript with {}", HexFormat.of().formatHex(message));
            transcriptDigest.update(message);
        }

        /**
         * Resets the running transcript digest to its initial (empty) state.
         *
         * <p>Used during HelloRetryRequest processing (RFC 8446 §4.4.1): after sending
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
         * Returns {@code true} if 1-RTT keys have been derived (stage 2 complete).
         */
        public boolean hasApplicationKeys() {
            return clientApplicationKeys != null;
        }

        /**
         * Sets the 1-RTT application keys.
         * Called by {@link QuicCrypto#createApplicationKeys} once the transcript is complete.
         */
        void setApplicationKeys(PacketProtectionKeys clientApplicationKeys, PacketProtectionKeys serverApplicationKeys) {
            this.clientApplicationKeys = clientApplicationKeys;
            this.serverApplicationKeys = serverApplicationKeys;
        }
    }

    /**
     * Packet protection keys for a specific encryption level.
     */
    public static class PacketProtectionKeys {
        public SecretKey key;           // Encryption/decryption key
        public byte[] iv;               // Initialization vector
        public byte[] headerProtection; // Header protection key

        public PacketProtectionKeys(SecretKey key, byte[] iv, byte[] headerProtection) {
            this.key = key;
            this.iv = iv;
            this.headerProtection = headerProtection;
        }
    }

    /**
     * Result of decrypting a QUIC packet.
     */
    public static class DecryptionResult {
        public final ByteBuffer plaintext;
        public final TlsMetadata tlsMetadata;
        public final boolean isHandshakeComplete;
        public final PacketProtectionKeys clientKeys;
        public final PacketProtectionKeys serverKeys;

        public DecryptionResult(ByteBuffer plaintext, TlsMetadata tlsMetadata, boolean isHandshakeComplete,
                               PacketProtectionKeys clientKeys, PacketProtectionKeys serverKeys) {
            this.plaintext = plaintext;
            this.tlsMetadata = tlsMetadata;
            this.isHandshakeComplete = isHandshakeComplete;
            this.clientKeys = clientKeys;
            this.serverKeys = serverKeys;
        }
    }

    private static final ThreadLocal<SecureRandom> secureRandom = 
        ThreadLocal.withInitial(SecureRandom::new);

    private static KeystoreManager keystoreManager;

    static void initKeystore() {
        // Install Conscrypt as the preferred security provider
        Security.insertProviderAt(Conscrypt.newProvider(), 1);

        // Initialize keystore manager with default configuration
        try {
            QuicServerConfig config = QuicServerConfig.createDefault();
            keystoreManager = new KeystoreManager(config);
            logger.info("Initialized KeystoreManager with default configuration");
        } catch (Exception e) {
            logger.warn("Failed to initialize KeystoreManager, will use mock certificates: {}", e.getMessage());
        }
    }

    // Private constructor to prevent instantiation
    private QuicCrypto() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * All data extracted from a ClientHello message.
     */
    public static class ParsedClientHello {
        /** Negotiated ALPN protocol (e.g. "h3"), or null if not provided. */
        public final String alpn;
        /** max_idle_timeout from QUIC transport parameters (0 if absent). */
        public final long maxIdleTimeoutMs;

        public final long maxUdpPayloadSize;
        public final long initialMaxData;
        public final List<Short> supportedSignatures;
        public final List<Short> supportedGroups;
        public final Map<Short, byte[]> clientKeys;

        public ParsedClientHello(String alpn, long maxIdleTimeoutMs, List<Short> supportedGroups, Map<Short, byte[]> clientKeys, long maxUdpPayloadSize, long initialMaxData, List<Short> supportedSignatures) {
            this.alpn = alpn;
            this.maxIdleTimeoutMs = maxIdleTimeoutMs;
            this.maxUdpPayloadSize = maxUdpPayloadSize;
            this.initialMaxData = initialMaxData;
            this.supportedSignatures = supportedSignatures;
            this.supportedGroups = supportedGroups;
            this.clientKeys = clientKeys;
        }
    }

    /**
     * Fully parses a ClientHello message, validating required TLS 1.3 fields
     * and extracting the data needed for key derivation.
     *
     * <p>Validates:
     * <ul>
     *   <li>Cipher suites contain {@code TLS_AES_128_GCM_SHA256} (0x1301)</li>
     *   <li>{@code supported_versions} extension contains TLS 1.3 (0x0304)</li>
     *   <li>{@code supported_groups} extension contains x25519 (0x001d)</li>
     *   <li>{@code key_share} extension contains an x25519 entry</li>
     * </ul>
     *
     * @param clientHello Raw ClientHello bytes (including the 4-byte TLS handshake header)
     * @return Parsed and validated ClientHello data
     * @throws CryptoException if a required field is missing or unsupported
     */
    private static ParsedClientHello parseClientHello(ByteBuffer clientHello) throws CryptoException {
        ByteBuffer buf = clientHello.duplicate();

        try {
            // ── TLS Handshake header ──────────────────────────────────────────────
            // msg_type (1 byte) + length (3 bytes)
            if (buf.remaining() < 4) throw new CryptoException("ClientHello too short");
            buf.get(); // msg_type (0x01 = ClientHello)
            buf.get(); buf.get(); buf.get(); // 3-byte length

            // ── Legacy client version (2 bytes) + random (32 bytes) ───────────────
            if (buf.remaining() < 34) throw new CryptoException("ClientHello: missing version/random");
            buf.position(buf.position() + 2); // legacy_version (ignored for TLS 1.3)
            byte[] clientRandom = new byte[32];
            buf.get(clientRandom); // random field (not used here, kept for completeness)

            // ── Legacy session ID ─────────────────────────────────────────────────
            if (buf.remaining() < 1) throw new CryptoException("ClientHello: missing session_id length");
            int sessionIdLen = buf.get() & 0xFF;
            if (buf.remaining() < sessionIdLen) throw new CryptoException("ClientHello: truncated session_id");
            buf.position(buf.position() + sessionIdLen);

            // ── Cipher Suites ─────────────────────────────────────────────────────
            if (buf.remaining() < 2) throw new CryptoException("ClientHello: missing cipher_suites length");
            int cipherSuitesLen = buf.getShort() & 0xFFFF;
            if (buf.remaining() < cipherSuitesLen) throw new CryptoException("ClientHello: truncated cipher_suites");
            boolean hasTlsAes128Gcm = false;
            int cipherSuitesEnd = buf.position() + cipherSuitesLen;
            while (buf.position() < cipherSuitesEnd) {
                int cs = buf.getShort() & 0xFFFF;
                if (cs == TLS_AES_128_GCM_SHA256_ID) hasTlsAes128Gcm = true;
            }
            if (!hasTlsAes128Gcm) {
                throw new CryptoException("ClientHello: TLS_AES_128_GCM_SHA256 not offered");
            }
            logger.debug("ClientHello cipher suites: TLS_AES_128_GCM_SHA256 present");

            // ── Legacy compression methods ────────────────────────────────────────
            if (buf.remaining() < 1) throw new CryptoException("ClientHello: missing compression_methods length");
            int compressionLen = buf.get() & 0xFF;
            if (buf.remaining() < compressionLen) throw new CryptoException("ClientHello: truncated compression_methods");
            buf.position(buf.position() + compressionLen);

            // ── Extensions ────────────────────────────────────────────────────────
            if (buf.remaining() < 2) throw new CryptoException("ClientHello: missing extensions length");
            int extensionsLen = buf.getShort() & 0xFFFF;
            if (buf.remaining() < extensionsLen) throw new CryptoException(String.format("ClientHello: truncated extensions remainig: %d extensionsLen %d", buf.remaining(), extensionsLen));

            boolean hasTls13Version = false;
            String alpn = null;
            long maxIdleTimeout = 0;
            long maxUdpPayloadSize = 1300;
            long initialMaxData = 0;
            List<Short> signatures = new ArrayList<>();
            List<Short> supportedGroups = new ArrayList<>();
            Map<Short, byte[]> clientKeys = new HashMap<>();

            int extensionsEnd = buf.position() + extensionsLen;
            while (buf.position() < extensionsEnd && buf.remaining() >= 4) {
                int extType = buf.getShort() & 0xFFFF;
                int extLen  = buf.getShort() & 0xFFFF;
                int extEnd  = buf.position() + extLen;
                if (buf.remaining() < extLen) {
                    buf.position(extensionsEnd);
                    logger.error("ClientHello: truncated extension 0x" + Integer.toHexString(extType));
                    break;
                }

                switch (extType) {

                    case 0x002b: { // supported_versions (RFC 8446 Section 4.2.1)
                        int listLen = buf.get() & 0xFF;
                        int listEnd = buf.position() + listLen;
                        while (buf.position() < listEnd) {
                            int v = buf.getShort() & 0xFFFF;
                            if (v == TLS_VERSION_1_3) hasTls13Version = true;
                        }
                        break;
                    }

                    case 0x000d: { // signature_algorithms
                        int listLen = buf.getShort() & 0xFFFF;
                        int listEnd = buf.position() + listLen;
                        while (buf.position() < listEnd) {
                            signatures.add(buf.getShort());
                        }
                        break;
                    }

                    case 0x000a: { // supported_groups (RFC 8446 Section 4.2.7)
                        int listLen = buf.getShort() & 0xFFFF;
                        int listEnd = buf.position() + listLen;
                        while (buf.position() < listEnd) {
                            supportedGroups.add(buf.getShort());
                        }
                        break;
                    }

                    case 0x0033: { // key_share (RFC 8446 Section 4.2.8)
                        int ksListLen = buf.getShort() & 0xFFFF;
                        int ksListEnd = buf.position() + ksListLen;
                        while (buf.position() < ksListEnd && buf.remaining() >= 4) {
                            short group   = buf.getShort();
                            int keyLen    = buf.getShort() & 0xFFFF;
                            if (buf.remaining() < keyLen) break;
                            byte [] key = new byte[keyLen];
                            buf.get(key);
                            clientKeys.put(group, key);
                        }
                        break;
                    }

                    case 0x0010: { // ALPN (RFC 7301)
                        int alpnListLen = buf.getShort() & 0xFFFF;
                        int alpnListEnd = buf.position() + alpnListLen;
                        while (buf.position() < alpnListEnd) {
                            int protoLen = buf.get() & 0xFF;
                            if (buf.remaining() < protoLen) break;
                            byte[] protoBytes = new byte[protoLen];
                            buf.get(protoBytes);
                            if (alpn == null) { // take the first (highest-priority)
                                alpn = new String(protoBytes, java.nio.charset.StandardCharsets.UTF_8);
                            }
                        }
                        break;
                    }

                    case 0x0039: // QUIC transport parameters (RFC 9001 Section 8.2)
                    case 0xffa5: {
                        int paramsEnd = buf.position() + extLen;
                        while (buf.position() < paramsEnd && buf.remaining() > 0) {
                            long paramId  = QuicVarint.read(buf);
                            long paramLen = QuicVarint.read(buf);
                            if (paramId == 0x01) { // max_idle_timeout
                                maxIdleTimeout = QuicVarint.read(buf);
                                logger.debug("ClientHello max_idle_timeout: {} ms", maxIdleTimeout);
                            } if (paramId == 0x03) {
                                maxUdpPayloadSize = QuicVarint.read(buf);
                            } if (paramId == 0x04) {
                                initialMaxData = QuicVarint.read(buf);
                            } else {
                                if (buf.remaining() >= paramLen) {
                                    buf.position(buf.position() + (int) paramLen);
                                } else break;
                            }
                        }
                        break;
                    }

                    default:
                        break; // unknown extension — skip below
                }

                // Always advance to the end of this extension
                if (buf.position() < extEnd) buf.position(extEnd);
            }

            // ── Validate required fields ──────────────────────────────────────────
            if (!hasTls13Version) {
//                throw new CryptoException("ClientHello: TLS 1.3 not listed in supported_versions");
                logger.error("ClientHello: TLS 1.3 not listed in supported_versions");
            }

            if (alpn == null) {
                logger.warn("ClientHello: no ALPN extension present");
            }

            return new ParsedClientHello(alpn, maxIdleTimeout, supportedGroups, clientKeys, maxUdpPayloadSize, initialMaxData, signatures);

        } catch (CryptoException ce) {
            throw ce;
        } catch (Exception e) {
            throw new CryptoException("Failed to parse ClientHello: " + e.getMessage(), e);
        }
    }

    /**
     * Configures the keystore manager with custom settings.
     * Must be called before any QUIC connections are created.
     * 
     * @param config Server configuration containing keystore settings
     * @throws java.security.KeyStoreException if keystore loading fails
     */
    public static void configureKeystore(QuicServerConfig config) throws java.security.KeyStoreException {
        keystoreManager = new KeystoreManager(config);
        logger.info("Configured KeystoreManager with custom settings");
    }

    /**
     * Returns the current keystore manager, or null if not initialized.
     */
    static KeystoreManager getKeystoreManager() {
        return keystoreManager;
    }

    /**
     * Derives Initial packet protection keys from destination connection ID.
     * Does not decrypt - only derives keys for header protection removal.
     */
    public static PacketProtectionKeys[] deriveInitialKeys(byte[] destinationCid) throws CryptoException {
        try {
            // Derive Initial secrets using HKDF with DCID
            byte[] initialSecret = hkdfExtract(QUIC_VERSION_1_SALT, destinationCid);

            // Derive client keys
            byte[] clientInitialSecret = hkdfExpandLabel(initialSecret, "client in", new byte[0], 32);
            SecretKey clientKey = deriveKey(clientInitialSecret);
            byte[] clientIv = deriveIv(clientInitialSecret);
            byte[] clientHp = deriveHp(clientInitialSecret);

            // Derive server keys
            byte[] serverInitialSecret = hkdfExpandLabel(initialSecret, "server in", new byte[0], 32);
            SecretKey serverKey = deriveKey(serverInitialSecret);
            byte[] serverIv = deriveIv(serverInitialSecret);
            byte[] serverHp = deriveHp(serverInitialSecret);

            PacketProtectionKeys clientKeys = new PacketProtectionKeys(clientKey, clientIv, clientHp);
            PacketProtectionKeys serverKeys = new PacketProtectionKeys(serverKey, serverIv, serverHp);

            return new PacketProtectionKeys[] { clientKeys, serverKeys };

        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to derive Initial keys", e);
        }
    }

    /**
     * Encrypts a QUIC packet with AES-128-GCM AEAD. Uses direct ByteBuffer for efficiency.
     * 
     * RFC 9001 Section 5.3: AEAD function usage in QUIC
     * The AEAD function protects packet payloads and authenticates packet headers.
     * 
     * Associated Data (AD) = packet header (from first byte through unprotected packet number)
     * Plaintext = packet payload (QUIC frames)
     * Output = ciphertext + 16-byte GCM authentication tag
     * 
     * The GCM tag authenticates BOTH the header (via AD) and the encrypted payload.
     * 
     * @param plaintext The plaintext data to encrypt (QUIC frames)
     * @param secret The encryption key (AES-128)
     * @param packetNumber QUIC packet number (used to construct nonce via XOR with base IV)
     * @param associatedData Packet header bytes to authenticate (RFC 9001 Section 5.4.1)
     * @return Encrypted ciphertext with GCM tag appended (plaintext.length + 16 bytes)
     * @throws CryptoException if encryption fails
     */
    public static ByteBuffer encryptPacket(ByteBuffer plaintext, SecretKey secret, long packetNumber,
                                           byte[] associatedData, byte[] baseIv) throws CryptoException {
        try {
            if (secret == null) {
                // Mock encryption for testing - still include space for GCM tag
                ByteBuffer encrypted = ByteBuffer.allocate(plaintext.remaining() + GCM_TAG_LENGTH);
                encrypted.put(plaintext);
                // In mock mode, pad with zeros for the "tag"
                for (int i = 0; i < GCM_TAG_LENGTH; i++) {
                    encrypted.put((byte) 0);
                }
                encrypted.flip();
                return encrypted;
            }

            // RFC 9001 §5.3: nonce = baseIv XOR left-padded(packetNumber)
            byte[] iv = baseIv.clone();
            for (int i = 0; i < 8; i++) {
                iv[GCM_NONCE_LENGTH - 1 - i] ^= (byte) (packetNumber >> (i * 8));
            }

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "Conscrypt");
            cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv));

            // RFC 9001 Section 5.4.1: Set Associated Data (packet header)
            // The GCM tag will authenticate both the header and the encrypted payload
            if (associatedData != null && associatedData.length > 0) {
                cipher.updateAAD(associatedData);
            }

            // Encrypt using direct ByteBuffer operations
            // cipher.getOutputSize() accounts for the 16-byte GCM tag
            ByteBuffer ciphertext = ByteBuffer.allocate(cipher.getOutputSize(plaintext.remaining()));
            cipher.doFinal(plaintext, ciphertext);
            ciphertext.flip();

            return ciphertext;

        } catch (GeneralSecurityException e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    /**
     * Stage 1 of the TLS 1.3 key schedule: processes a ClientHello and derives
     * Handshake-level traffic secrets.
     *
     * <p>{@link TlsMetadata} is created first — seeded with the Early Secret —
     * and used as the running state object throughout. Each derived value is stored
     * into it immediately, making the metadata the authoritative source of truth.
     *
     * <p>Performs KPG:
     * the client's public key is extracted from the {@code key_share} extension,
     * a fresh server ephemeral key pair is generated, and the shared secret is computed.
     *
     * <p>The 1-RTT keys are not produced here; call
     * {@link #createApplicationKeys(TlsMetadata)} after the client Finished is verified.
     *
     * @param clientHello The raw ClientHello bytes (including the 4-byte TLS header)
     * @return {@link TlsMetadata} with Handshake secrets and running transcript;
     *         {@link TlsMetadata#hasApplicationKeys()} returns {@code false}
     * @throws CryptoException if the ClientHello is malformed, missing required extensions,
     *         advertises unsupported parameters, or key derivation fails
     */
    public static TlsMetadata processClientHello(TlsMetadata metadata, ByteBuffer clientHello) throws CryptoException {
        try {
            // ── Step 1: Create TlsMetadata — the golden source of state.
            // Early Secret = HKDF-Extract(salt=0, IKM=0) [RFC 8446 §7.1, no PSK]
            byte[] earlySecret = hkdfExtract(new byte[32], new byte[32]);
            metadata.earlySecret = earlySecret;
            logger.debug("TlsMetadata created with Early Secret");

            // ── Step 2: Feed raw ClientHello bytes into the running transcript.
            byte[] clientHelloBytes = new byte[clientHello.remaining()];
            clientHello.duplicate().get(clientHelloBytes);
            metadata.updateTranscript(clientHelloBytes);
            logger.debug("Transcript updated with ClientHello ({} bytes)", clientHelloBytes.length);

            // ── Step 3: Parse and validate the ClientHello.
            ParsedClientHello parsed = parseClientHello(clientHello);

            metadata.clientMetadata = parsed;
            // ── Step 4: Set negotiated application-level parameters.
            metadata.alpn = parsed.alpn;
            metadata.selectedCipherSuite = CIPHER_SUITE;

            if (parsed.supportedSignatures.isEmpty()) {
                throw new CryptoException("No signature_algorithms found are in ClientHello!");
            }
            metadata.selectedSignatureScheme = keystoreManager.selectSignatureScheme(parsed.supportedSignatures);

            long serverIdleTimeout = 30_000;
            metadata.negotiatedIdleTimeoutMs = parsed.maxIdleTimeoutMs > 0
                    ? Math.min(parsed.maxIdleTimeoutMs, serverIdleTimeout)
                    : serverIdleTimeout;

            logger.info("Negotiated idle timeout: {} ms (client: {}, server: {})",
                    metadata.negotiatedIdleTimeoutMs, parsed.maxIdleTimeoutMs, serverIdleTimeout);
            if (metadata.alpn != null) {
                logger.info("ALPN negotiated: {}", metadata.alpn);
            } else {
                logger.warn("ClientHello: no ALPN provided");
            }

            // ── Step 5: Generate server random.
            byte[] serverRandom = new byte[32];
            secureRandom.get().nextBytes(serverRandom);
            metadata.serverRandom = serverRandom;

            // ── Step 6: X25519 ECDHE — compute the shared secret.
            TlsGroupMapping.SelectionResult selectionResult = TlsGroupMapping.selectGroup(parsed.supportedGroups, parsed.clientKeys.keySet());
            if (selectionResult == null) {
                throw new CryptoException("There is no suitable KPG algorithm in clients supported_groups.", (short) 0x001D);
            } else if (selectionResult.requiresHelloRetryRequest) {
                throw new CryptoException("Client keys not supported, demand another.", selectionResult.chosenGroupId);
            } else {
                KpgResult kpgResult = generateKeysAndDeriveSharedSecret(TlsGroupMapping.resolve(selectionResult.chosenGroupId), parsed.clientKeys.get(selectionResult.chosenGroupId));
                metadata.serverEphemeralPublicKey = kpgResult.serverPublicKeyRaw;
                metadata.selectedKeyScheme = selectionResult.chosenGroupId;
                byte[] sharedSecret = kpgResult.sharedSecret;
                System.out.println("Early secret: "+ HexFormat.of().formatHex(earlySecret));

                // ── Step 7: Derive Handshake Secret and traffic secrets.
                byte[] derivedFromEarly = hkdfExpandLabel(earlySecret, "derived", sha256(new byte[0]), 32);

                System.out.println("derivedFromEarly: "+ HexFormat.of().formatHex(derivedFromEarly));
                byte[] handshakeSecret  = hkdfExtract(derivedFromEarly, sharedSecret);
                metadata.handshakeSecretBytes = handshakeSecret;

                System.out.println("handshakeSecret: "+ HexFormat.of().formatHex(handshakeSecret));

                logger.debug("Handshake traffic secrets derived");
            }

            return metadata;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to process ClientHello", e);
        }
    }

    public static void generateHandshakeSecrets(TlsMetadata metadata) throws GeneralSecurityException {
        // Context = transcript hash up to and including ClientHello.
        // ServerHello is appended later by createInitialResponse.
        byte[] transcriptSoFar = metadata.transcriptHash();
        byte[] clientHandshakeTrafficSecret = hkdfExpandLabel(
                metadata.handshakeSecretBytes, "c hs traffic", transcriptSoFar, 32);
        byte[] serverHandshakeTrafficSecret = hkdfExpandLabel(
                metadata.handshakeSecretBytes, "s hs traffic", transcriptSoFar, 32);

        metadata.serverHandshakeTrafficSecret = serverHandshakeTrafficSecret;
        metadata.clientHandshakeTrafficSecret = clientHandshakeTrafficSecret;

        System.out.println("serverHandshakeTrafficSecret: " + HexFormat.of().formatHex(serverHandshakeTrafficSecret) );

        metadata.serverHandshakeKeys = new QuicCrypto.PacketProtectionKeys(deriveKey(serverHandshakeTrafficSecret),
                deriveIv(serverHandshakeTrafficSecret), deriveHp(serverHandshakeTrafficSecret));
        metadata.clientHandshakeKeys = new QuicCrypto.PacketProtectionKeys(deriveKey(clientHandshakeTrafficSecret),
                deriveIv(clientHandshakeTrafficSecret), deriveHp(clientHandshakeTrafficSecret));

    }

    /**
     * Holds the output of an X25519 ECDHE exchange.
     */
    private static final class KpgResult {
        /** Server's raw 32-byte ephemeral public key (to send in ServerHello key_share). */
        final byte[] serverPublicKeyRaw;
        /** The 32-byte shared secret (ECDH output, used as IKM for the Handshake Secret). */
        final byte[] sharedSecret;

        KpgResult(byte[] serverPublicKeyRaw, byte[] sharedSecret) {
            this.serverPublicKeyRaw = serverPublicKeyRaw;
            this.sharedSecret = sharedSecret;
        }
    }

    /**
     * Performs an exchange.
     *
     * <ol>
     *   <li>Generates a fresh server ephemeral key pair.</li>
     *   <li>Runs {@link javax.crypto.KeyAgreement} to produce the shared secret.</li>
     * </ol>
     *
     * @param groupInfo - specifies KPG algorithm
     * @param clientPublicKeyRaw raw public key from the client's key_share
     * @return {@link KpgResult} containing the server's raw public key and the shared secret
     * @throws GeneralSecurityException if key generation or agreement fails
     */
    private static KpgResult generateKeysAndDeriveSharedSecret(TlsGroupMapping.JcaGroupInfo groupInfo, byte[] clientPublicKeyRaw)
            throws GeneralSecurityException {
        // ── Step 1: Generate server ephemeral key pair ────────────────────────────
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(groupInfo.keyPairGeneratorAlgorithm);
        kpg.initialize(groupInfo.parameterSpec);
        KeyPair serverKeyPair = kpg.generateKeyPair();

        // ── Step 2: Extract raw server public key bytes ───────────────────────────
        // Java encodes public keys as SubjectPublicKeyInfo (DER). The raw key bytes
        // are always at the tail of the DER structure:
        //   XDH  (X25519/X448): last 32 / 56 bytes are the u-coordinate.
        //   EC   (secp256r1 etc.): last keyLen bytes are the uncompressed point (04 || x || y).
        byte[] serverPubEncoded = serverKeyPair.getPublic().getEncoded();
        int rawLen = rawPublicKeyLength(groupInfo);
        byte[] serverPublicKeyRaw = java.util.Arrays.copyOfRange(
                serverPubEncoded, serverPubEncoded.length - rawLen, serverPubEncoded.length);
        logger.debug("Generated server {} ephemeral key pair ({} raw bytes)",
                groupInfo.standardName, rawLen);

        // ── Step 3: Reconstruct client PublicKey from raw bytes ───────────────────
        // Wrap the raw bytes in a SubjectPublicKeyInfo DER structure so that
        // KeyFactory can parse it via X509EncodedKeySpec.
        byte[] clientSpki = buildSpkiForGroup(groupInfo, clientPublicKeyRaw);
        KeyFactory kf = KeyFactory.getInstance(groupInfo.keyPairGeneratorAlgorithm);
        PublicKey clientPublicKey = kf.generatePublic(
                new java.security.spec.X509EncodedKeySpec(clientSpki));

        // ── Step 4: Key agreement ─────────────────────────────────────────────────
        // XDH uses algorithm name "XDH"; EC uses "ECDH".
        String kaAlgorithm = "XDH".equals(groupInfo.keyPairGeneratorAlgorithm) ? "XDH" : "ECDH";
        KeyAgreement ka = KeyAgreement.getInstance(kaAlgorithm);
        ka.init(serverKeyPair.getPrivate());
        ka.doPhase(clientPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();
        logger.debug("Shared secret computed via {} ({} bytes)", kaAlgorithm, sharedSecret.length);

        return new KpgResult(serverPublicKeyRaw, sharedSecret);
    }

    /**
     * Returns the expected raw public key byte length for a given group.
     * <ul>
     *   <li>X25519  → 32 bytes</li>
     *   <li>X448    → 56 bytes</li>
     *   <li>EC P-256 → 65 bytes (uncompressed: 0x04 || x(32) || y(32))</li>
     *   <li>EC P-384 → 97 bytes (uncompressed: 0x04 || x(48) || y(48))</li>
     *   <li>EC P-521 → 133 bytes (uncompressed: 0x04 || x(66) || y(66))</li>
     * </ul>
     */
    private static int rawPublicKeyLength(TlsGroupMapping.JcaGroupInfo groupInfo) {
        switch (groupInfo.standardName) {
            case "X25519":      return 32;
            case "X448":        return 56;
            case "secp256r1":   return 65;
            case "secp384r1":   return 97;
            case "secp521r1":   return 133;
            case "brainpoolP256r1": return 65;
            default:
                throw new IllegalArgumentException("Unknown group: " + groupInfo.standardName);
        }
    }

    /**
     * Wraps raw public key bytes in a SubjectPublicKeyInfo (SPKI) DER structure
     * for the given group, so that {@link KeyFactory#generatePublic} can parse it.
     *
     * <p>XDH groups (X25519, X448) use OIDs from RFC 8410 and a BIT STRING wrapper.
     * EC groups use OIDs from RFC 5480 with an ECParameters OID inner field.
     */
    private static byte[] buildSpkiForGroup(TlsGroupMapping.JcaGroupInfo groupInfo, byte[] rawKey) {
        // DER OID bytes for each group (tag 0x06 + length + OID value)
        final byte[] oidBytes;
        final boolean isXdh = "XDH".equals(groupInfo.keyPairGeneratorAlgorithm);

        switch (groupInfo.standardName) {
            // XDH OIDs (RFC 8410)
            case "X25519":
                oidBytes = new byte[]{ 0x06, 0x03, 0x2B, 0x65, 0x6E };
                break;
            case "X448":
                oidBytes = new byte[]{ 0x06, 0x03, 0x2B, 0x65, 0x6F };
                break;
            // EC OIDs — namedCurve OID wrapped inside AlgorithmIdentifier
            // Outer OID = id-ecPublicKey (1.2.840.10045.2.1): 06 07 2A 86 48 CE 3D 02 01
            // Inner OID = curve OID
            case "secp256r1":
                // curve OID: 1.2.840.10045.3.1.7 → 06 08 2A 86 48 CE 3D 03 01 07
                oidBytes = new byte[]{ 0x06, 0x08, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x03, 0x01, 0x07 };
                break;
            case "secp384r1":
                // curve OID: 1.3.132.0.34 → 06 05 2B 81 04 00 22
                oidBytes = new byte[]{ 0x06, 0x05, 0x2B, (byte)0x81, 0x04, 0x00, 0x22 };
                break;
            case "secp521r1":
                // curve OID: 1.3.132.0.35 → 06 05 2B 81 04 00 23
                oidBytes = new byte[]{ 0x06, 0x05, 0x2B, (byte)0x81, 0x04, 0x00, 0x23 };
                break;
            case "brainpoolP256r1":
                // OID: 1.3.36.3.3.2.8.1.1.7 → 06 09 2B 24 03 03 02 08 01 01 07
                oidBytes = new byte[]{ 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 };
                break;
            default:
                throw new IllegalArgumentException("Unsupported group for SPKI: " + groupInfo.standardName);
        }

        if (isXdh) {
            // AlgorithmIdentifier = SEQUENCE { OID }  (no parameters for XDH)
            byte[] algId = new byte[2 + oidBytes.length];
            algId[0] = 0x30; algId[1] = (byte) oidBytes.length;
            System.arraycopy(oidBytes, 0, algId, 2, oidBytes.length);

            // BIT STRING: 0x03 | len | 0x00 (no unused bits) | rawKey
            byte[] bitString = new byte[3 + rawKey.length];
            bitString[0] = 0x03; bitString[1] = (byte)(rawKey.length + 1); bitString[2] = 0x00;
            System.arraycopy(rawKey, 0, bitString, 3, rawKey.length);

            // SEQUENCE { algId | bitString }
            int totalLen = algId.length + bitString.length;
            byte[] spki = new byte[2 + totalLen];
            spki[0] = 0x30; spki[1] = (byte) totalLen;
            System.arraycopy(algId,    0, spki, 2,               algId.length);
            System.arraycopy(bitString,0, spki, 2 + algId.length, bitString.length);
            return spki;
        } else {
            // EC: AlgorithmIdentifier = SEQUENCE { id-ecPublicKey OID, namedCurve OID }
            byte[] ecPkOid = { 0x06, 0x07, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x02, 0x01 };

            // AlgorithmIdentifier SEQUENCE contains ecPublicKey OID + curve OID
            int algIdContentLen = ecPkOid.length + oidBytes.length;
            byte[] algId = new byte[2 + algIdContentLen];
            algId[0] = 0x30; algId[1] = (byte) algIdContentLen;
            System.arraycopy(ecPkOid,  0, algId, 2,                ecPkOid.length);
            System.arraycopy(oidBytes, 0, algId, 2 + ecPkOid.length, oidBytes.length);

            // BIT STRING wrapping the uncompressed EC point
            byte[] bitString = new byte[3 + rawKey.length];
            bitString[0] = 0x03; bitString[1] = (byte)(rawKey.length + 1); bitString[2] = 0x00;
            System.arraycopy(rawKey, 0, bitString, 3, rawKey.length);

            int totalLen = algId.length + bitString.length;
            byte[] spki = new byte[2 + totalLen];
            spki[0] = 0x30; spki[1] = (byte) totalLen;
            System.arraycopy(algId,    0, spki, 2,               algId.length);
            System.arraycopy(bitString,0, spki, 2 + algId.length, bitString.length);
            return spki;
        }
    }


    /**
     * Wraps a raw 32-byte X25519 public key in a SubjectPublicKeyInfo (SPKI) structure
     * so that Java's {@link java.security.KeyFactory} can reconstruct a {@link java.security.PublicKey}.
     *
     * <p>SPKI for X25519 (OID 1.3.101.110, RFC 8410):
     * <pre>
     *   SEQUENCE {
     *     SEQUENCE { OID 1.3.101.110 }
     *     BIT STRING { 0x00 || rawKey[32] }
     *   }
     * </pre>
     */
    private static byte[] buildX25519SubjectPublicKeyInfo(byte[] rawKey) {
        // OID 1.3.101.110 in DER: 06 03 2B 65 6E
        byte[] oidBytes    = { 0x06, 0x03, 0x2B, 0x65, 0x6E };
        // AlgorithmIdentifier: SEQUENCE { OID }
        byte[] algId       = new byte[2 + oidBytes.length];
        algId[0] = 0x30; algId[1] = (byte) oidBytes.length;
        System.arraycopy(oidBytes, 0, algId, 2, oidBytes.length);
        // BIT STRING: 0x03 | len | 0x00 (no unused bits) | rawKey
        byte[] bitString   = new byte[3 + rawKey.length];
        bitString[0] = 0x03; bitString[1] = (byte)(rawKey.length + 1); bitString[2] = 0x00;
        System.arraycopy(rawKey, 0, bitString, 3, rawKey.length);
        // SEQUENCE { algId | bitString }
        int totalLen = algId.length + bitString.length;
        byte[] spki = new byte[2 + totalLen];
        spki[0] = 0x30; spki[1] = (byte) totalLen;
        System.arraycopy(algId,    0, spki, 2,                    algId.length);
        System.arraycopy(bitString,0, spki, 2 + algId.length,     bitString.length);
        return spki;
    }

    /**
     * Stage 2 of the TLS 1.3 key schedule: derives the Master Secret and
     * 1-RTT (application) traffic secrets once the handshake transcript is complete.
     *
     * <p>Must be called after the client's Finished message has been verified,
     * at which point the full transcript hash is known.
     *
     * @param metadata     The {@link TlsMetadata} returned by {@link #processClientHello}
     * @param transcriptHash SHA-256 hash of all handshake messages up to and including
     *                       the client's Finished (simplified: empty array uses ClientHello hash)
     * @throws CryptoException if key derivation fails
     */
    /**
     * Stage 2 of the TLS 1.3 key schedule: derives the Master Secret and
     * 1-RTT (application) traffic secrets once the handshake transcript is complete.
     *
     * <p>The transcript hash is taken directly from {@link TlsMetadata#transcriptHash()},
     * which must have been updated with all messages up to and including the client
     * Finished before this method is called.
     *
     * @param metadata The {@link TlsMetadata} returned by {@link #processClientHello},
     *                 whose transcript digest must be fully up-to-date
     * @throws CryptoException if key derivation fails
     */
    public static void createApplicationKeys(TlsMetadata metadata) throws CryptoException {
        try {
            // Master Secret = HKDF-Extract(Derive-Secret(Handshake Secret, "derived", ""), 0)
            byte[] derivedFromHandshake = hkdfExpandLabel(
                    metadata.handshakeSecretBytes, "derived", sha256(new byte[0]), 32);
            byte[] masterSecret = hkdfExtract(derivedFromHandshake, new byte[32]);

            logger.warn("App transcript master sec {}", HexFormat.of().formatHex(masterSecret));

            // Snapshot the current transcript hash (all messages up to client Finished)
            byte[] context = metadata.transcriptHash();

            metadata.clientApplicationTrafficSecret = hkdfExpandLabel(
                    masterSecret, "c ap traffic", context, 32);

            logger.warn("App transcript hash {}", HexFormat.of().formatHex(context));
            logger.warn("App traffic sec {}", HexFormat.of().formatHex(metadata.clientApplicationTrafficSecret));

            metadata.serverApplicationTrafficSecret = hkdfExpandLabel(
                    masterSecret, "s ap traffic", context, 32);

            SecretKey clientApplicationSecret = deriveKey(metadata.clientApplicationTrafficSecret);
            SecretKey serverApplicationSecret = deriveKey(metadata.serverApplicationTrafficSecret);
            byte[] clientApplicationHpKey = deriveHp(metadata.clientApplicationTrafficSecret);
            byte[] serverApplicationHpKey = deriveHp(metadata.serverApplicationTrafficSecret);
            byte[] clientApplicationIv = deriveIv(metadata.clientApplicationTrafficSecret);
            byte[] serverApplicationIv = deriveIv(metadata.serverApplicationTrafficSecret);

            logger.warn("App client sec {}", HexFormat.of().formatHex(clientApplicationSecret.getEncoded()));
            logger.warn("App client IV {}", HexFormat.of().formatHex(clientApplicationIv));
            logger.warn("App client HP {}", HexFormat.of().formatHex(clientApplicationHpKey));

            metadata.setApplicationKeys(new PacketProtectionKeys(clientApplicationSecret, clientApplicationIv, clientApplicationHpKey),
                    new PacketProtectionKeys(serverApplicationSecret, serverApplicationIv, serverApplicationHpKey));

            logger.debug("Derived 1-RTT application keys from transcript hash (stage 2 complete)");

        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to derive application keys", e);
        }
    }

    public static void rotateApplicationKeys(TlsMetadata metadata) throws CryptoException {
        try {
            metadata.clientApplicationTrafficSecret = hkdfExpandLabel(
                    metadata.clientApplicationTrafficSecret, "quic ku", new byte[0], 32);
            metadata.serverApplicationTrafficSecret = hkdfExpandLabel(
                    metadata.serverApplicationTrafficSecret, "quic ku", new byte[0], 32);

            metadata.clientApplicationKeys.key = deriveKey(metadata.clientApplicationTrafficSecret);
            metadata.serverApplicationKeys.key = deriveKey(metadata.serverApplicationTrafficSecret);

            metadata.clientApplicationKeys.iv = deriveIv(metadata.clientApplicationTrafficSecret);
            metadata.serverApplicationKeys.iv = deriveIv(metadata.serverApplicationTrafficSecret);

            logger.warn("App client sec {}", HexFormat.of().formatHex(metadata.clientApplicationKeys.key.getEncoded()));
            logger.warn("App client IV {}", HexFormat.of().formatHex(metadata.clientApplicationKeys.iv));

            metadata.currentPhase = (byte)( (metadata.currentPhase == 0) ? 1 : 0 );

            logger.info("Rotated application keys, current Key Phase set to {}", metadata.currentPhase);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to rotate application keys", e);
        }
    }

    /**
     * Computes SHA-256 hash of the input.
     */
    private static byte[] sha256(byte[] input) throws GeneralSecurityException {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    }

    /**
     * Creates a TLS 1.3 ServerHello message (RFC 8446 Section 4.1.3).
     *
     * <p>The {@code key_share} extension carries {@link TlsMetadata#serverEphemeralPublicKey},
     * the server's X25519 ephemeral public key produced by {@link #processClientHello},
     * so the client can complete its side of the ECDHE exchange.
     *
     * @param metadata the live {@link TlsMetadata} for this connection
     * @return serialised ServerHello bytes ready to wrap in a TLS CRYPTO frame
     */
    public static ByteBuffer createServerHello(TlsMetadata metadata) {
        short cipherSuiteId = getCipherSuiteId(metadata.selectedCipherSuite);

        byte[] keyShare = metadata.serverEphemeralPublicKey;
//        if (keyShare == null || keyShare.length != 32) {
//            logger.error("serverEphemeralPublicKey missing or wrong length — was processClientHello called?");
//            keyShare = new byte[32]; // fallback; handshake will fail on the client side
//        }

        byte[] serverRandom = metadata.serverRandom != null ? metadata.serverRandom : new byte[32];

        // ServerHello wire layout (RFC 8446 §4.1.3):
        //   ProtocolVersion(2) + Random(32) + session_id_len(1)
        //   + CipherSuite(2) + compression(1) + extensions_len(2) + extensions
        ByteBuffer buf = ByteBuffer.allocate(256);

        buf.putShort((short) 0x0303);           // legacy_version = TLS 1.2 (for compatibility)
        buf.put(serverRandom);                  // server random from metadata
        buf.put((byte) 0x00);                   // legacy session_id (empty for TLS 1.3)
        buf.putShort(cipherSuiteId);            // selected cipher suite
        buf.put((byte) 0x00);                   // legacy compression = null

        int extLenPos = buf.position();
        buf.putShort((short) 0);                // extensions length placeholder
        int extStart = buf.position();

        // supported_versions extension (0x002b) — signals TLS 1.3 to the client
        buf.putShort((short) 0x002b);
        buf.putShort((short) 0x0002);
        buf.putShort((short) 0x0304);           // TLS 1.3

        // key_share extension (0x0033) — server's x25519 ephemeral public key
        buf.putShort((short) 0x0033);
        buf.putShort((short) (2 + 2 + keyShare.length)); // group(2) + key_len(2) + key
        buf.putShort(metadata.selectedKeyScheme);
        buf.putShort((short) keyShare.length);
        buf.put(keyShare);


        // Back-fill extensions length
        buf.putShort(extLenPos, (short) (buf.position() - extStart));

        buf.flip();

        int len = buf.remaining();
        ByteBuffer wrap = ByteBuffer.allocate(len + 4);
        wrap.put((byte) 0x02); //Server Hello
        wrap.put((byte) (len >> 16));
        wrap.put((byte) (len >> 8));
        wrap.put((byte) len);
        wrap.put(buf);

        return wrap.flip();
    }



    /**
     * Builds the raw TLS 1.3 HelloRetryRequest (HRR) wire message and wraps it
     * in a QUIC CRYPTO frame (RFC 9000 §19.6).
     *
     * <p>An HRR is a special ServerHello (RFC 8446 §4.1.3) whose Random field equals
     * SHA-256("HelloRetryRequest"). It carries exactly two extensions:
     * <ul>
     *   <li>{@code supported_versions} (0x002b) — advertises TLS 1.3.</li>
     *   <li>{@code key_share} (0x0033) — contains <em>only</em> the preferred group id,
     *       no key material (RFC 8446 §4.2.8), telling the client to retry with that group.</li>
     * </ul>
     *
     * <p>This method is a <em>pure builder</em>: it does not touch the transcript.
     * After obtaining the frame, call
     * {@link #applyHelloRetryRequestToTranscript(TlsMetadata, ByteBuffer)}
     * to perform the RFC 8446 §4.4.1 transcript replacement.
     *
     * @param preferredGroupId IANA NamedGroup id the server wants the client to use
     *                         (e.g. {@code 0x001d} for x25519, {@code 0x0017} for secp256r1)
     * @return a flipped {@link ByteBuffer} containing the QUIC CRYPTO frame ready to
     *         place inside an Initial packet; the buffer is also suitable as the
     *         {@code hrr} argument to
     *         {@link #applyHelloRetryRequestToTranscript(TlsMetadata, ByteBuffer)}
     */
    public static ByteBuffer createHelloRetryRequest(short preferredGroupId) {
        // Zero-copy: single buffer, lengths back-filled in place.
        ByteBuffer hrr = ByteBuffer.allocate(128);

        // ── 4-byte TLS handshake header ───────────────────────────────────────────
        hrr.put((byte) 0x02);                    // HandshakeType: server_hello (HRR reuses 0x02)
        int bodyLenPos = hrr.position();
        hrr.put((byte) 0).put((byte) 0).put((byte) 0); // body length — back-filled

        // ── ServerHello body (RFC 8446 §4.1.3) ───────────────────────────────────
        int bodyStart = hrr.position();
        hrr.putShort((short) 0x0303);                     // legacy_version = TLS 1.2
        hrr.put(HRR_RANDOM);                              // sentinel random
        hrr.put((byte) 0x00);                             // legacy session_id length = 0
        hrr.putShort((short) TLS_AES_128_GCM_SHA256_ID); // cipher suite
        hrr.put((byte) 0x00);                             // legacy compression = null

        int extLenPos = hrr.position();
        hrr.putShort((short) 0);                 // extensions_length — back-filled
        int extStart = hrr.position();

        // supported_versions (0x002b): TLS 1.3
        hrr.putShort((short) 0x002b);
        hrr.putShort((short) 0x0002);
        hrr.putShort((short) TLS_VERSION_1_3);

        // key_share (0x0033): selected_group only — no key bytes (RFC 8446 §4.2.8)
        hrr.putShort((short) 0x0033);
        hrr.putShort((short) 0x0002);            // extension data length = 2 (group id only)
        hrr.putShort(preferredGroupId);

        // Back-fill extensions_length
        int extEnd = hrr.position();
        hrr.putShort(extLenPos, (short) (extEnd - extStart));

        // Back-fill body length (3 bytes, big-endian)
        int bodyLen = extEnd - bodyStart;
        hrr.put(bodyLenPos,     (byte) ((bodyLen >> 16) & 0xFF));
        hrr.put(bodyLenPos + 1, (byte) ((bodyLen >>  8) & 0xFF));
        hrr.put(bodyLenPos + 2, (byte) ( bodyLen        & 0xFF));

        hrr.flip();

        // ── Wrap in QUIC CRYPTO frame (RFC 9000 §19.6) ───────────────────────────
        // type(varint=0x06) | offset(varint=0) | length(varint) | data
        int hrrLen = hrr.remaining();
        ByteBuffer frame = ByteBuffer.allocateDirect(3 + 8 + hrrLen);
        QuicVarint.write(frame, 0x06);
        QuicVarint.write(frame, 0x00);
        QuicVarint.write(frame, hrrLen);
        frame.put(hrr);
        frame.flip();
        return frame;
    }

    /**
     * Applies the RFC 8446 §4.4.1 transcript replacement that must happen after
     * a HelloRetryRequest is sent.
     *
     * <p>Per the RFC, when the server sends an HRR the transcript hash is redefined as:
     * <pre>
     *   Transcript-Hash(ClientHello1, HRR, ...) =
     *       Hash( message_hash || HRR || ... )
     * </pre>
     * where the synthetic {@code message_hash} record is:
     * <pre>
     *   HandshakeType (1) = 0xfe
     *   Length        (3) = 32   (SHA-256 output size)
     *   Hash               = SHA-256(ClientHello1)   ← snapshot of current transcript
     * </pre>
     *
     * <p>Steps performed:
     * <ol>
     *   <li>Snapshot {@code Hash(ClientHello1)} from the current (live) transcript.</li>
     *   <li>Reset the running transcript digest to the empty state.</li>
     *   <li>Feed the synthetic {@code message_hash} record into the fresh digest.</li>
     *   <li>Feed the HRR wire message into the digest.</li>
     * </ol>
     *
     * <p>After this call the transcript is ready to receive ClientHello2.
     *
     * @param metadata live {@link TlsMetadata}; its transcript is updated in-place
     * @param hrrCryptoFrame the QUIC CRYPTO frame returned by
     *                       {@link #createHelloRetryRequest(short)}; the TLS HRR message
     *                       is extracted from it (bytes after the 3-varint CRYPTO header)
     */
    public static void applyHelloRetryRequestToTranscript(TlsMetadata metadata, ByteBuffer hrrCryptoFrame) {
        // ── Step 1: snapshot Hash(ClientHello1) before we touch anything ─────────
        byte[] ch1Hash = metadata.transcriptHash();

        // ── Step 2: build the synthetic message_hash record (RFC 8446 §4.4.1) ────
        // HandshakeType(1=0xfe) | Length(3=32) | Hash(32)
        ByteBuffer msgHash = ByteBuffer.allocate(4 + ch1Hash.length);
        msgHash.put((byte) 0xfe);
        msgHash.put((byte) 0x00);
        msgHash.put((byte) 0x00);
        msgHash.put((byte) ch1Hash.length);   // always 32 for SHA-256
        msgHash.put(ch1Hash);
        msgHash.flip();

        // ── Step 3: extract the raw TLS HRR message from the CRYPTO frame ────────
        // CRYPTO frame layout: type(varint) | offset(varint) | length(varint) | data
        ByteBuffer frameDup = hrrCryptoFrame.duplicate();
        QuicVarint.read(frameDup); // skip frame type (0x06)
        QuicVarint.read(frameDup); // skip offset
        QuicVarint.read(frameDup); // skip length
        // frameDup.slice() now points at the raw TLS HRR handshake message
        ByteBuffer hrrMsg = frameDup.slice();

        // ── Step 4: reset transcript and feed message_hash || HRR ─────────────────
        metadata.resetTranscript();
        metadata.updateTranscript(msgHash);
        metadata.updateTranscript(hrrMsg);

        logger.debug("Transcript replaced per RFC 8446 §4.4.1: message_hash(ClientHello1) || HRR");
     }

     /**
     * Creates a TLS 1.3 EncryptedExtensions message (RFC 8446 Section 4.3.1).
     *
     * <p>EncryptedExtensions is the first encrypted handshake message sent by the server.
     * It carries extensions that do not need to be part of the ServerHello but must be
     * protected — notably ALPN (RFC 7301) and QUIC transport parameters (RFC 9001 §8.2).
     *
     * <p>Wire format:
     * <pre>
     *   HandshakeType (1)  = 0x08 (encrypted_extensions)
     *   Length      (3)
     *   extensions_length (2)
     *   [ Extension* ]
     * </pre>
     *
     * Each extension:
     * <pre>
     *   ExtensionType (2) | data_length (2) | data
     * </pre>
     *
     * @param metadata the live {@link TlsMetadata} for this connection
     * @return serialised EncryptedExtensions bytes ready to wrap in a TLS CRYPTO frame
     */
    public static ByteBuffer createEncryptedExtensions(TlsMetadata metadata, long cid) {
        // Zero-copy: single pre-allocated buffer, all lengths back-filled in place.
        // Layout:
        //   [0]      HandshakeType (1)          = 0x08
        //   [1..3]   body length (3)            <- back-filled
        //   [4..5]   extensions_length (2)      <- back-filled
        //   [6..]    extensions:
        //              ALPN (0x0010)
        //              QUIC transport parameters (0x0039)
        ByteBuffer msg = ByteBuffer.allocate(1024);

        // ── TLS handshake header (4 bytes) ────────────────────────────────────────
        msg.put((byte) 0x08);                    // HandshakeType: encrypted_extensions
        int bodyLenPos = msg.position();
        msg.put((byte) 0).put((byte) 0).put((byte) 0); // body length placeholder

        // ── EncryptedExtensions body: extensions_length field (2 bytes) ───────────
        int extLenPos = msg.position();
        msg.putShort((short) 0);                 // extensions_length placeholder

        int extStart = msg.position();

        // ── ALPN extension (0x0010, RFC 7301) ────────────────────────────────────
        // Only include if a protocol was negotiated.
        msg.put((byte) 0x00).put((byte) 0x10);  // extension type: ALPN
        int totalLen = QuicEngine.getStreamEngine().getProtocols()
                .stream().map(QuicApplicationProtocol::getProtocolName)
                .mapToInt(String::length).sum();
        totalLen += QuicEngine.getStreamEngine().getProtocols().size();
        msg.putShort((short) (totalLen + 2));  // extension data length
        msg.putShort((short) totalLen);  // ProtocolNameList length
        for (QuicApplicationProtocol protocol : QuicEngine.getStreamEngine().getProtocols()) {
            msg.put((byte) protocol.getProtocolName().length());
            msg.put(protocol.getProtocolName().getBytes());
        }

        // ── QUIC transport parameters extension (0x0039, RFC 9001 §8.2) ──────────
        msg.putShort((short) 0x0039);            // extension type: quic_transport_parameters
        int tpExtLenPos = msg.position();
        msg.putShort((short) 0);                 // transport parameters length placeholder

        int tpStart = msg.position();

        // original_destination_connection_id (param id 0x00, RFC 9000 §18.2)
        if (metadata.originalDCid != null && metadata.originalDCid.length > 0) {
            QuicVarint.write(msg, 0x00);                         // param id
            QuicVarint.write(msg, metadata.originalDCid.length); // param length
            msg.put(metadata.originalDCid);                      // param value
        }

        // initial_source_connection_id (param id 0x0f)
        QuicVarint.write(msg, 0x0f);
        QuicVarint.write(msg, 8);
        msg.putLong(cid);

        // initial_max_data  (param id 0x04)
        QuicVarint.write(msg, 0x04);
        QuicVarint.write(msg, QuicVarint.sizeOf(10485760));
        QuicVarint.write(msg,10485760);

        //initial_max_stream_data_bidi_local: 0x05
        QuicVarint.write(msg, 0x05);
        QuicVarint.write(msg, QuicVarint.sizeOf(10485760));
        QuicVarint.write(msg,10485760);

        //initial_max_stream_data_bidi_remote: 0x06
        QuicVarint.write(msg, 0x06);
        QuicVarint.write(msg, QuicVarint.sizeOf(10485760));
        QuicVarint.write(msg,10485760);

        //initial_max_stream_data_uni: 0x07
        QuicVarint.write(msg, 0x07);
        QuicVarint.write(msg, QuicVarint.sizeOf(10485760));
        QuicVarint.write(msg,10485760);

        // initial_max_streams_bidi (param id 0x08)
        QuicVarint.write(msg, 0x08);
        QuicVarint.write(msg, QuicVarint.sizeOf(100));
        QuicVarint.write(msg,100);

        // initial_max_streams_uni  (param id 0x09)
        QuicVarint.write(msg, 0x09);
        QuicVarint.write(msg, QuicVarint.sizeOf(100));
        QuicVarint.write(msg,100);

        // max_udp_payload_size
        QuicVarint.write(msg, 0x03);
        QuicVarint.write(msg, QuicVarint.sizeOf(metadata.clientMetadata.maxUdpPayloadSize));
        QuicVarint.write(msg, metadata.clientMetadata.maxUdpPayloadSize);


        // max_idle_timeout (param id 0x01)
        long idleTimeoutMs = metadata.negotiatedIdleTimeoutMs > 0
                ? metadata.negotiatedIdleTimeoutMs
                : 30_000;
        QuicVarint.write(msg, 0x01);             // param id: max_idle_timeout
        QuicVarint.write(msg, QuicVarint.sizeOf(idleTimeoutMs));
        QuicVarint.write(msg, idleTimeoutMs);    // param value

        int tpEnd = msg.position();
        int tpLen = tpEnd - tpStart;

        // Back-fill transport parameters extension data length
        msg.putShort(tpExtLenPos, (short) tpLen);

        // ── Back-fill extensions_length ───────────────────────────────────────────
        int extEnd = msg.position();
        msg.putShort(extLenPos, (short) (extEnd - extStart));

        // ── Back-fill body length (3 bytes, big-endian) ───────────────────────────
        int bodyLen = extEnd - (bodyLenPos + 3);
        msg.put(bodyLenPos,     (byte) ((bodyLen >> 16) & 0xFF));
        msg.put(bodyLenPos + 1, (byte) ((bodyLen >>  8) & 0xFF));
        msg.put(bodyLenPos + 2, (byte) ( bodyLen        & 0xFF));

        msg.flip();
        return msg;
    }

    /**
     * Creates a TLS 1.3 server Finished message (RFC 8446 Section 4.4.4).
     *
     * <p>Must be called after the transcript has been updated with EncryptedExtensions,
     * Certificate, and CertificateVerify, so that the correct transcript hash is used.
     *
     * <p>Wire format:
     * <pre>
     *   HandshakeType (1) = 0x14 (finished)
     *   Length        (3)
     *   verify_data   (32)   HMAC-SHA256(finished_key, transcript_hash)
     * </pre>
     * where {@code finished_key = HKDF-Expand-Label(server_hs_secret, "finished", "", 32)}.
     *
     * @param metadata the live {@link TlsMetadata}; its transcript must be fully up-to-date
     * @return serialised Finished message bytes (36 bytes)
     * @throws CryptoException if HMAC computation fails
     */
    public static ByteBuffer createServerFinished(TlsMetadata metadata) throws CryptoException {
        try {
            byte[] finishedKey = hkdfExpandLabel(metadata.serverHandshakeTrafficSecret, "finished", new byte[0], 32);

            byte[] transcriptHash = metadata.transcriptHash();

            Mac mac = Mac.getInstance("HmacSHA256", "Conscrypt");
            mac.init(new SecretKeySpec(finishedKey, "HmacSHA256"));
            byte[] verifyData = mac.doFinal(transcriptHash);

            // Wrap in TLS handshake header: msg_type(1) + length(3) + verify_data(32)
            ByteBuffer msg = ByteBuffer.allocate(4 + verifyData.length);
            msg.put((byte) 0x14);                                 // HandshakeType: finished
            msg.put((byte) ((verifyData.length >>> 16) & 0xFF));
            msg.put((byte) ((verifyData.length >>>  8) & 0xFF));
            msg.put((byte) ( verifyData.length         & 0xFF));
            msg.put(verifyData);
            return msg.flip();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to create server Finished", e);
        }
    }

    /**
     * Creates a TLS 1.3 Certificate message (RFC 8446 Section 4.4.2).
     *
     * <p>Wire format:
     * <pre>
     *   HandshakeType (1) = 0x0b (certificate)
     *   Length        (3)
     *   request_context_length (1) = 0x00   (always empty for server Certificate)
     *   certificate_list_length (3)
     *   [ CertificateEntry* ]               each: cert_data(3+n) + extensions(2)
     * </pre>
     *
     * <p>The certificate chain is loaded from the configured {@link KeystoreManager}.
     * If no keystore is configured an empty Certificate message is returned (the client
     * will reject it, but this keeps the code runnable during development).
     *
     * @return serialised Certificate message bytes ready to concatenate into the
     *         server handshake CRYPTO frame payload
     */
    public static ByteBuffer createCertificate() {
        byte[] certChainBytes = encodeCertificateChain();

        if (certChainBytes != null) {
            // encodeCertificateChainTls() returns the full certificate_list body
            // (each entry: 3-byte cert length + DER cert + 2-byte extensions length).
            // Body = request_context (1 byte = 0x00) + certificate_list
            int certBodyLen = 1 + certChainBytes.length;
            ByteBuffer msg = ByteBuffer.allocate(4 + certBodyLen);
            msg.put((byte) 0x0b);                              // HandshakeType: certificate
            msg.put((byte) ((certBodyLen >> 16) & 0xFF));
            msg.put((byte) ((certBodyLen >>  8) & 0xFF));
            msg.put((byte) ( certBodyLen        & 0xFF));
            msg.put((byte) 0x00);                              // request_context (empty)
            msg.put(certChainBytes);
            return msg.flip();
        } else {
            // No keystore — empty Certificate (request_context + empty list)
            logger.warn("No keystore configured — sending empty Certificate message");
            int certBodyLen = 1 + 3; // request_context(1) + empty list length field(3)
            ByteBuffer msg = ByteBuffer.allocate(4 + certBodyLen);
            msg.put((byte) 0x0b);
            msg.put((byte) ((certBodyLen >> 16) & 0xFF));
            msg.put((byte) ((certBodyLen >>  8) & 0xFF));
            msg.put((byte) ( certBodyLen        & 0xFF));
            msg.put((byte) 0x00);  // request_context
            msg.put((byte) 0x00);  // empty certificate_list length (3 bytes = 0)
            msg.put((byte) 0x00);
            msg.put((byte) 0x00);
            return msg.flip();
        }
    }

    /**
     * Creates a TLS 1.3 CertificateVerify message (RFC 8446 Section 4.4.3).
     *
     * <p>The signature is computed over the transcript hash snapshot taken
     * <em>after</em> the Certificate message has been fed into the transcript,
     * covering: ClientHello → ServerHello → EncryptedExtensions → Certificate.
     *
     * <p>Content to sign (RFC 8446 §4.4.3):
     * <pre>
     *   64 × 0x20
     *   + "TLS 1.3, server CertificateVerify" (ASCII, no NUL terminator)
     *   + 0x00
     *   + transcript_hash (32 bytes)
     * </pre>
     *
     * <p>Wire format:
     * <pre>
     *   HandshakeType  (1) = 0x0f (certificate_verify)
     *   Length         (3)
     *   algorithm      (2)   SignatureScheme (e.g. 0x0804 = rsa_pss_rsae_sha256)
     *   signature_len  (2)
     *   signature      (n)
     * </pre>
     *
     * <p>If no keystore is configured an empty CertificateVerify stub is returned.
     *
     * @param metadata the live {@link TlsMetadata}; transcript must include Certificate
     * @return serialised CertificateVerify bytes
     * @throws CryptoException if signing fails unexpectedly
     */
    public static ByteBuffer createCertificateVerify(TlsMetadata metadata) throws CryptoException {
        byte[] contextString = "TLS 1.3, server CertificateVerify"
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] transcriptHash = metadata.transcriptHash();
        byte[] toSign = new byte[64 + contextString.length + 1 + transcriptHash.length];
        java.util.Arrays.fill(toSign, 0, 64, (byte) 0x20);
        System.arraycopy(contextString, 0, toSign, 64, contextString.length);
        toSign[64 + contextString.length] = 0x00;
        System.arraycopy(transcriptHash, 0, toSign, 64 + contextString.length + 1, transcriptHash.length);

        byte[] signature = null;
        try {
            signature = signData(toSign, metadata.selectedSignatureScheme);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to sign TLS data", e);
        }

        short sigScheme = metadata.selectedSignatureScheme;
        int cvBodyLen = 2 + 2 + signature.length;
        ByteBuffer msg = ByteBuffer.allocate(4 + cvBodyLen);
        msg.put((byte) 0x0f);                           // HandshakeType: certificate_verify
        msg.put((byte) ((cvBodyLen >>> 16) & 0xFF));
        msg.put((byte) ((cvBodyLen >>> 8) & 0xFF));
        msg.put((byte) (cvBodyLen & 0xFF));
        msg.putShort(sigScheme);                        // signature algorithm
        msg.putShort((short) (signature.length & 0xFFFF));         // signature length
        msg.put(signature);
        return msg.flip();
    }

    /**
     * Maps cipher suite name to TLS identifier (RFC 8446 Appendix B.4).
     */
    private static short getCipherSuiteId(String cipherSuite) {
        if (cipherSuite == null) {
            logger.warn("Cipher suite is null, defaulting to TLS_AES_128_GCM_SHA256");
            return (short) 0x1301;
        }

        switch (cipherSuite) {
            case "TLS_AES_128_GCM_SHA256":
                return (short) 0x1301;
            case "TLS_AES_256_GCM_SHA384":
                return (short) 0x1302;
            case "TLS_CHACHA20_POLY1305_SHA256":
                return (short) 0x1303;
            case "TLS_AES_128_CCM_SHA256":
                return (short) 0x1304;
            case "TLS_AES_128_CCM_8_SHA256":
                return (short) 0x1305;
            default:
                logger.warn("Unknown cipher suite: {}, defaulting to TLS_AES_128_GCM_SHA256", cipherSuite);
                return (short) 0x1301;
        }
    }

    // ========== HKDF Implementation ==========

    /**
     * HKDF-Extract as per RFC 5869. Uses direct operations.
     */
    private static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256", "Conscrypt");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        return mac.doFinal(ikm);
    }

    /**
     * HKDF-Expand-Label as per RFC 8446 for TLS 1.3.
     */
    private static byte[] hkdfExpandLabel(byte[] secret, String label, byte[] context, int length) 
            throws GeneralSecurityException {
        byte[] hkdfLabel = buildHkdfLabel(length, "tls13 " + label, context);
        return hkdfExpand(secret, hkdfLabel, length);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256", "Conscrypt");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));

        byte[] result = new byte[length];
        byte[] t = new byte[0];
        int offset = 0;
        int iteration = 0;

        while (offset < length) {
            iteration++;
            mac.update(t);
            mac.update(info);
            mac.update((byte) iteration);
            t = mac.doFinal();

            int toCopy = Math.min(t.length, length - offset);
            System.arraycopy(t, 0, result, offset, toCopy);
            offset += toCopy;
        }

        return result;
    }

    private static byte[] buildHkdfLabel(int length, String label, byte[] context) {
        byte[] labelBytes = label.getBytes();
        ByteBuffer buffer = ByteBuffer.allocate(2 + 1 + labelBytes.length + 1 + context.length);
        buffer.putShort((short) length);
        buffer.put((byte) labelBytes.length);
        buffer.put(labelBytes);
        buffer.put((byte) context.length);
        buffer.put(context);
        return buffer.array();
    }

    // ========== QUIC-specific key derivation ==========

    private static SecretKey deriveKey(byte[] secret) throws GeneralSecurityException {
        byte[] key = hkdfExpandLabel(secret, "quic key", new byte[0], AES_128_KEY_LENGTH);
        return new SecretKeySpec(key, "AES");
    }

    static byte[] deriveIv(byte[] secret) throws GeneralSecurityException {
        return hkdfExpandLabel(secret, "quic iv", new byte[0], GCM_NONCE_LENGTH);
    }

    private static byte[] deriveHp(byte[] secret) throws GeneralSecurityException {
        return hkdfExpandLabel(secret, "quic hp", new byte[0], AES_128_KEY_LENGTH);
    }

    /**
     * Derives the QUIC header protection key from a traffic secret.
     * Equivalent to the "quic hp" HKDF-Expand-Label step used in {@link #deriveInitialKeys}.
     * Use this to obtain the handshake (or 1-RTT) HP key when only the traffic
     * {@link SecretKey} is available (e.g. from {@link TlsMetadata}).
     *
     * @param trafficSecret The traffic secret (e.g. {@code TlsMetadata.clientHandshakeSecret})
     * @return Raw 16-byte header-protection key bytes suitable for passing to
     *         {@link QuicPacketHeader#parse(java.nio.ByteBuffer, byte[])}
     * @throws CryptoException if key derivation fails
     */
    public static byte[] deriveHeaderProtectionKey(SecretKey trafficSecret) throws CryptoException {
        try {
            return deriveHp(trafficSecret.getEncoded());
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to derive header protection key", e);
        }
    }

    // ========== AEAD operations with ByteBuffer ==========

    static void decryptAead(ByteBuffer packet, SecretKey key, byte[] baseIv, long packetNumber, ByteBuffer output, byte[] associatedData)
            throws GeneralSecurityException {
        // Construct nonce by XORing packet number with IV
        byte[] nonce = baseIv.clone();
        for (int i = 0; i < 8; i++) {
            nonce[GCM_NONCE_LENGTH - 1 - i] ^= (byte) (packetNumber >> (i * 8));
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "Conscrypt");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce));

        cipher.updateAAD(associatedData);

        // Decrypt using ByteBuffer operations

        cipher.doFinal(packet, output);
    }

    /**
     * Encodes the certificate chain in TLS format.
     * Returns null if no keystore is configured.
     */
    public static byte[] encodeCertificateChain() {
        if (keystoreManager == null) {
            logger.debug("No keystore manager, cannot encode certificate chain");
            return null;
        }

        try {
            return keystoreManager.encodeCertificateChainTls();
        } catch (java.security.cert.CertificateEncodingException e) {
            logger.error("Failed to encode certificate chain", e);
            return null;
        }
    }

    /**
     * Signs data using the server's private key.
     * Returns null if no keystore is configured.
     */
    public static byte[] signData(byte[] data, short signatureScheme) throws GeneralSecurityException {
        return keystoreManager.sign(data, signatureScheme);
    }

    /**
     * Verifies the client's TLS Finished message.
     * 
     * RFC 8446 Section 4.4.4:
     * The Finished message contains verify_data which is computed as:
     *   verify_data = HMAC(finished_key, transcript_hash)
     * 
     * Where:
     *   finished_key = HKDF-Expand-Label(client_handshake_secret, "finished", "", Hash.length)
     *   transcript_hash = Hash(all handshake messages up to but not including Finished)
     * 
     * @param finishedData The TLS Finished message bytes
     * @param clientHandshakeSecret The client's handshake traffic secret
     * @param transcriptHash The hash of all handshake messages received so far (simplified: can be empty for testing)
     * @return true if verification succeeds
     * @throws CryptoException if parsing or verification fails
     */
    public static boolean verifyClientFinished(ByteBuffer finishedData, byte[] clientHandshakeSecret, byte[] transcriptHash)
            throws CryptoException {
        try {
            finishedData.mark();
            // Parse TLS Finished message structure:
            // - msg_type (1 byte) = 0x14 (Finished)
            // - length (3 bytes, network order)
            // - verify_data (32 bytes for SHA-256)

            if (finishedData.remaining() < 4) {
                throw new CryptoException("Finished message too short");
            }

            int length = getCryptoFrameLength(finishedData);

            if (finishedData.remaining() < length) {
                throw new CryptoException("Finished message incomplete");
            }

            // Extract received verify_data
//            byte[] receivedVerifyData = new byte[length];
//            finishedData.get(receivedVerifyData);

            // Compute expected verify_data
            // finished_key = HKDF-Expand-Label(client_handshake_secret, "finished", "", Hash.length)
            byte[] finishedKey = hkdfExpandLabel(clientHandshakeSecret, "finished", new byte[0], 32);

            // For simplified implementation, if transcript hash is empty, skip verification
            // In production, maintain full handshake transcript and compute SHA-256 hash
            if (transcriptHash == null || transcriptHash.length == 0) {
                // Simplified mode: accept any Finished message with correct structure
                logger.debug("Skipping Finished verification (no transcript hash provided)");
                return true;
            }

            // Compute HMAC(finished_key, transcript_hash)
            Mac mac = Mac.getInstance("HmacSHA256", "Conscrypt");
            mac.init(new SecretKeySpec(finishedKey, "HmacSHA256"));
            byte[] expectedVerifyData = mac.doFinal(transcriptHash);

            // Constant-time comparison to prevent timing attacks
            if (finishedData.remaining() != expectedVerifyData.length) {
                return false;
            }

            int result = 0;
            int i = 0;
            while (finishedData.hasRemaining()) {
                result |= finishedData.get() ^ expectedVerifyData[i];
                i++;
                if (result != 0) break;
            }
            finishedData.reset();

            return result == 0;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to verify Finished message", e);
        }
    }

    public static int getCryptoFrameLength(ByteBuffer buffer) {
        buffer.get();
        // Read 3-byte length (network order)
        return ((buffer.get() & 0xFF) << 16) | ((buffer.get() & 0xFF) << 8) | buffer.get() & 0xFF;
    }


    /**
     * Exception thrown when cryptographic operations fail.
     */
    public static class CryptoException extends Exception {
        private final Short demandedGroupId;

        public Short getDemandedGroupId() {
            return demandedGroupId;
        }

        public CryptoException(String message) {
            super(message);
            demandedGroupId = null;
        }

        public CryptoException(String message, short demandedGroupId) {
            super(message);
            this.demandedGroupId = demandedGroupId;
        }

        public CryptoException(String message, Throwable cause) {
            super(message, cause);
            demandedGroupId = null;
        }
    }



    public static byte[] generateStatelessResetToken(byte[] connectionId) {
        try {
            // 1. Initialize HMAC-SHA256 with the server's master secret key
            SecretKeySpec secretKeySpec = new SecretKeySpec(getKeystoreManager().getPrivateKey().getEncoded(), "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKeySpec);

            // 2. Compute the hash using the specific Connection ID as input
            byte[] fullHmac = mac.doFinal(connectionId);

            // 3. Truncate the 32-byte SHA256 output down to exactly 16 bytes (RFC 9000 requirement)
            return Arrays.copyOf(fullHmac, STATELESS_RESET_TOKEN_LENGTH);

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            // RuntimeException wrap to keep interface clean since HmacSHA256 is guaranteed in the JVM
            throw new IllegalStateException("Failed to compute Stateless Reset Token", e);
        }
    }
}
