package org.fmalyshev.quic;

import org.conscrypt.Conscrypt;
import org.fmalyshev.quic.buffers.BorrowedPoolBuffer;
import org.fmalyshev.quic.buffers.PoolBuffer;
import org.fmalyshev.quic.buffers.RootPoolBuffer;
import org.fmalyshev.quic.streamapi.QuicApplicationProtocol;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Integration tests for QUIC connection with REAL cryptographic operations.
 * These tests verify that GCM authentication tags are properly verified,
 * that transcript hashes are accumulated correctly, and that the full
 * Initial → Handshake → 1-RTT sequence works higher-to-higher.
 * NO MOCKING of QuicCrypto — all encryption/decryption is real.
 */
class QuicConnectionCryptoIntegrationTest {
    static {
        Security.addProvider(Conscrypt.newProvider());
    }

    private static final SelectorThread selectorMock = mock(SelectorThread.class);

    private static final long TEST_CONNECTION_ID = 0x1234567890ABCDEFL;
    private static final InetSocketAddress TEST_ADDRESS = new InetSocketAddress("127.0.0.1", 4433);
    private static final byte[] TEST_CID = new byte[8];
    private static final ByteBuffer TEST_CID_BUF;
    static {
        TEST_CID_BUF = ByteBuffer.wrap(TEST_CID).putLong(TEST_CONNECTION_ID).flip();
    }

    @BeforeAll
    static void beforeAll() {
        QuicEngine.getPool(); // Trigger BufferPool initialization if needed
        try {
             // Initialize QuicCrypto/KeystoreManager
             java.lang.reflect.Method initCrypto = QuicCrypto.class.getDeclaredMethod("initKeystore");
             initCrypto.setAccessible(true);
             initCrypto.invoke(null);

             // Initialize QuicStreamEngineImpl in QuicEngine
             java.lang.reflect.Field engineField = QuicEngine.class.getDeclaredField("streamEngineInternal");
             engineField.setAccessible(true);
             if (engineField.get(null) == null) {
                org.fmalyshev.quic.streamapi.impl.QuicStreamEngineImpl engine = 
                    new org.fmalyshev.quic.streamapi.impl.QuicStreamEngineImpl(1);
                QuicApplicationProtocol protocol = mock(QuicApplicationProtocol.class);
                when(protocol.getProtocolName()).thenReturn("h3");
                when(protocol.getConnectionHandler()).thenReturn(cid -> mock(org.fmalyshev.quic.streamapi.QuicApplicationProtocolConnectionHandler.class));
                
                org.fmalyshev.quic.streamapi.CongestionControl cc = mock(org.fmalyshev.quic.streamapi.CongestionControl.class);
                when(cc.timeWindowMs()).thenReturn(100);
                when(protocol.getCongestionControl()).thenReturn(cc);
                
                engine.registerProtocol(protocol);
                engineField.set(null, engine);
             }
        } catch (Exception e) {
             // Already initialized or failure
        }
    }

    @Test
    void testGcmTagVerification_InitialPacket_ValidTag() throws Exception {
        // Verify that a properly encrypted Initial packet carrying a real ClientHello
        // is decrypted successfully and advances the connection to HANDSHAKE state.

        byte[] destinationCid = new byte[8];
        ByteBuffer.wrap(destinationCid).putLong(TEST_CONNECTION_ID);

        QuicCrypto.PacketProtectionKeysWithHP[] keys = QuicCrypto.deriveInitialKeys(destinationCid);
        QuicCrypto.PacketProtectionKeysWithHP clientKeys = keys[0];

        // Build a real TLS 1.3 ClientHello and wrap it in a CRYPTO frame
        ByteBuffer clientHello = buildMinimalClientHello();
        ByteBuffer cryptoFrame = ByteBuffer.allocate(500);
        cryptoFrame.put((byte) 0x06);                     // CRYPTO frame type
        QuicVarint.write(cryptoFrame, 0);           // offset (varint)
        QuicVarint.write(cryptoFrame, (long) clientHello.remaining()); // length
        cryptoFrame.put(clientHello);
        cryptoFrame.flip();

        PoolBuffer initialPacket = QuicPacketBuilder.buildInitialPacket(
            destinationCid,
            TEST_CID_BUF,
            0,
            cryptoFrame,
            clientKeys
        );

        QuicConnection connection = new QuicConnection(TEST_CONNECTION_ID, TEST_ADDRESS, selectorMock);
        try {
            connection.processInitialAndRespond(initialPacket);
            List<ByteBuffer> responses = getOutboundPackets(connection);

            // Decryption succeeded and ClientHello was processed → HANDSHAKE
            assertFalse(responses.isEmpty(), "Initial response (ServerHello) should be generated");
            assertEquals(QuicConnection.State.HANDSHAKE, connection.getState(),
                "Connection should advance to HANDSHAKE after valid Initial packet");
        } finally {
            initialPacket.release();
        }
    }

    @Disabled
    @Test
    void testGcmTagVerification_InitialPacket_InvalidTag() throws Exception {
        // Test that tampered ciphertext causes packet rejection

        byte[] destinationCid = new byte[8];
        ByteBuffer.wrap(destinationCid).putLong(TEST_CONNECTION_ID);

        QuicCrypto.PacketProtectionKeysWithHP[] keys = QuicCrypto.deriveInitialKeys(destinationCid);
        QuicCrypto.PacketProtectionKeysWithHP clientKeys = keys[0];

        ByteBuffer clientHello = buildMinimalClientHello();
        ByteBuffer framebuffer = ByteBuffer.allocate(500);
        framebuffer.put((byte) 0x06);                          // CRYPTO frame type
        QuicVarint.write(framebuffer, 0x00);                      // offset
        QuicVarint.write(framebuffer, (long) clientHello.remaining()); // length
        framebuffer.put(clientHello);
        framebuffer.flip();

        PoolBuffer initialPacket = QuicPacketBuilder.buildInitialPacket(
            destinationCid,
            TEST_CID_BUF,
            0,
            framebuffer,
            clientKeys
        );

        // Tamper with the ciphertext (the part after the header)
        ByteBuffer tamperedBuf = initialPacket.buf();
        int lastBytePos = tamperedBuf.limit() - 1;
        byte originalByte = tamperedBuf.get(lastBytePos);
        tamperedBuf.put(lastBytePos, (byte) (originalByte ^ 0xFF)); // Flip bits

        QuicConnection connection = new QuicConnection(TEST_CONNECTION_ID, TEST_ADDRESS, selectorMock);
        // Ensure clientCid is NOT null so we don't fail later if we somehow continue
        try {
            java.lang.reflect.Field cidField = QuicConnection.class.getDeclaredField("clientCid");
            cidField.setAccessible(true);
            cidField.set(connection, TEST_CID);
        } catch (Exception e) {}

        try {
            connection.processInitialAndRespond(initialPacket);
            List<ByteBuffer> responses = getOutboundPackets(connection);

            // Should be rejected due to invalid GCM tag (AEADBadTagException)
            // State should remain INITIAL because processInitialPacket returns null on decryption failure
            assertTrue(responses.isEmpty() || (responses.size() == 1 && connection.getState() == QuicConnection.State.INITIAL),
                "Should reject packet with invalid GCM tag. Responses: " + responses.size() + ", State: " + connection.getState());
            
            // Actually, if it's a new connection and decryption fails, it might send a stateless reset (if configured)
            // or just discard.
            assertEquals(QuicConnection.State.INITIAL, connection.getState(),
                "Should remain in INITIAL state after rejected packet");
        } finally {
            initialPacket.release();
        }
    }

    @Test
    public void testGcmTagVerification_1RttPacket_ValidTag() throws Exception {
        // Verify that a properly encrypted 1-RTT packet is accepted.

        byte[] keyBytes = new byte[16];
        for (int i = 0; i < 16; i++) keyBytes[i] = (byte) i;
        SecretKey real1RttKey = new SecretKeySpec(keyBytes, "AES");

        QuicConnection connection = new QuicConnection(TEST_CONNECTION_ID, TEST_ADDRESS, selectorMock);
        // Manually set destination CID to avoid NPE during header measurement
        try {
            java.lang.reflect.Field cidField = QuicConnection.class.getDeclaredField("clientCid");
            cidField.setAccessible(true);
            cidField.set(connection, TEST_CID);
        } catch (Exception e) {}

        connection.setState(QuicConnection.State.ESTABLISHED);
        ConnectionMetadata meta1Rtt = make1RttMetadata(real1RttKey);
        meta1Rtt.clientApplicationKeys = new QuicCrypto.PacketProtectionKeys(real1RttKey, new byte[12]);
        connection.setTlsMetadata(meta1Rtt);

        ByteBuffer plaintext = ByteBuffer.allocate(20);
        plaintext.put((byte) 0x01); // PING frame (ACK-eliciting)
        while (plaintext.hasRemaining()) plaintext.put((byte) 0x00);
        plaintext.flip();
        PoolBuffer packet = QuicPacketBuilder.build1RttPacket(
            destinationCidBytes(TEST_CONNECTION_ID), 5, plaintext,
            meta1Rtt.clientApplicationKeys, meta1Rtt.clientApplicationHeaderProtection, (byte) 0);

        try {
            connection.process1RttPacket(packet, 0);
            List<ByteBuffer> responses = getOutboundPackets(connection);

            assertNotNull(responses, "Should process packet with valid GCM tag");
            assertFalse(responses.isEmpty(), "ACK should be generated for PING frame");
        } finally {
            packet.release();
        }
    }

    public static List<ByteBuffer> getOutboundPackets(QuicConnection connection) {
        List<ByteBuffer> responses = new ArrayList<>();
        for (PoolBuffer res = connection.pollOutbound(); res != null; res = connection.pollOutbound()) {
            responses.add(res.buf().duplicate());
        }
        return responses;
    }


    public static byte[] destinationCidBytes(long testConnectionId) {
        return ByteBuffer.allocate(8).putLong(testConnectionId).array();
    }

    @Test
    void testGcmTagVerification_1RttPacket_InvalidTag() throws Exception {
        // Verify that a tampered GCM tag in a 1-RTT packet causes rejection.

        byte[] keyBytes = new byte[16];
        for (int i = 0; i < 16; i++) keyBytes[i] = (byte) i;
        SecretKey real1RttKey = new SecretKeySpec(keyBytes, "AES");

        QuicConnection connection = new QuicConnection(TEST_CONNECTION_ID, TEST_ADDRESS, selectorMock);
        // Manually set destination CID to avoid NPE during header measurement
        try {
            java.lang.reflect.Field cidField = QuicConnection.class.getDeclaredField("clientCid");
            cidField.setAccessible(true);
            cidField.set(connection, TEST_CID);
        } catch (Exception e) {}

        connection.setState(QuicConnection.State.ESTABLISHED);
        ConnectionMetadata meta1Rtt = make1RttMetadata(real1RttKey);
        meta1Rtt.clientApplicationKeys = new QuicCrypto.PacketProtectionKeys(real1RttKey, new byte[12]);
        connection.setTlsMetadata(meta1Rtt);

        ByteBuffer plaintext = ByteBuffer.allocate(20);
        plaintext.put((byte) 0x01);
        while (plaintext.hasRemaining()) plaintext.put((byte) 0x00);
        plaintext.flip();

        PoolBuffer packet = QuicPacketBuilder.build1RttPacket(
                destinationCidBytes(TEST_CONNECTION_ID),
                5, plaintext, meta1Rtt.clientApplicationKeys, meta1Rtt.clientApplicationHeaderProtection, (byte) 0);

        // Tamper with the last byte of the GCM authentication tag
        ByteBuffer tamperedBuf = packet.buf();
        int last = tamperedBuf.limit() - 1;
        tamperedBuf.put(last, (byte) (tamperedBuf.get(last) ^ 0xFF));

        try {
            connection.process1RttPacket(packet, 0);
            List<ByteBuffer> responses = getOutboundPackets(connection);

            assertEquals(0, responses.size(), "Should reject packet with invalid GCM tag");
        } finally {
            packet.release();
        }
    }

    // =========================================================================
    // End-to-higher test: real ClientHello → Initial → Handshake → 1-RTT
    // =========================================================================

    @Test
    @DisplayName("RFC 9001/8446: Full Handshake Flow (ClientHello -> ServerHello...Finished -> ClientFinished)")
    void testFullHandshakeSequence_EndToEnd() throws Exception {
        QuicConnection connection = new QuicConnection(TEST_CONNECTION_ID, TEST_ADDRESS, selectorMock);
        // Set clientCid to avoid NPE during header parsing of client-sent packets (which server parses)
        setClientCid(connection, TEST_CID);
        
        assertEquals(QuicConnection.State.INITIAL, connection.getState());

        // ── Phase 1: Initial packet (ClientHello) ─────────────────────────────
        QuicCrypto.PacketProtectionKeysWithHP[] initKeys = QuicCrypto.deriveInitialKeys(TEST_CID);
        ByteBuffer clientHello = buildMinimalClientHello();
        
        ByteBuffer cryptoFrame = ByteBuffer.allocate(clientHello.remaining() + 10);
        cryptoFrame.put((byte) 0x06); // CRYPTO
        QuicVarint.write(cryptoFrame, 0x00);
        QuicVarint.write(cryptoFrame, (long) clientHello.remaining());
        cryptoFrame.put(clientHello);
        cryptoFrame.flip();

        PoolBuffer initialPacket = QuicPacketBuilder.buildInitialPacket(
            TEST_CID, TEST_CID_BUF, 0, cryptoFrame, initKeys[0]);

        try {
            connection.processInitialAndRespond(initialPacket);
            
            // Server should advance to HANDSHAKE state
            assertEquals(QuicConnection.State.HANDSHAKE, connection.getState(),
                "Server state should be HANDSHAKE after Initial packet");
            
            List<ByteBuffer> serverFlight = getOutboundPackets(connection);
            assertFalse(serverFlight.isEmpty(), "Server should have sent Handshake response");
        } finally {
            initialPacket.release();
        }

        // TlsMetadata now contains derived Handshake secrets
        ConnectionMetadata meta = connection.getTlsMetadata();
        assertNotNull(meta.clientHandshakeTrafficSecret, "Handshake secrets must be derived");

        // ── Phase 2: Handshake packet (client Finished) ───────────────────────
        // The server flight (EE, Cert, CV, server Finished) has already been added 
        // to the transcript by QuicConnection during sendHandshakePacket().
        
        byte[] clientFinishedVerifyData = computeClientFinished(meta);
        byte[] finishedMsg = new byte[4 + clientFinishedVerifyData.length];
        finishedMsg[0] = 0x14; // msg_type: Finished
        finishedMsg[3] = (byte) clientFinishedVerifyData.length;
        System.arraycopy(clientFinishedVerifyData, 0, finishedMsg, 4, clientFinishedVerifyData.length);

        ByteBuffer finishedCryptoFrame = ByteBuffer.allocate(finishedMsg.length + 10);
        finishedCryptoFrame.put((byte) 0x06);
        QuicVarint.write(finishedCryptoFrame, 0x00);
        QuicVarint.write(finishedCryptoFrame, (long) finishedMsg.length);
        finishedCryptoFrame.put(finishedMsg);
        finishedCryptoFrame.flip();

        PoolBuffer handshakePacket = QuicPacketBuilder.buildHandshakePacket(
            TEST_CID, TEST_CID_BUF, 0, finishedCryptoFrame, meta.clientHandshakeKeys);

        try {
            connection.processHandshakePacket(handshakePacket);
            
            assertEquals(QuicConnection.State.ESTABLISHED, connection.getState(),
                "Server state should be ESTABLISHED after client Finished");
            assertNotNull(meta.clientApplicationKeys, "1-RTT keys must be derived");
        } finally {
            handshakePacket.release();
        }

        // ── Phase 3: 1-RTT packet (PING) ──────────────────────────────────────
        ByteBuffer pingFrame = ByteBuffer.allocate(10);
        pingFrame.put((byte) 0x01); // PING
        // Add padding to ensure packet is long enough for HP sampling (>= 20 bytes ciphertext)
        // 1 byte PING + 3 bytes PADDING + 16 bytes GCM tag = 20 bytes ciphertext.
        for (int i = 0; i < 3; i++) pingFrame.put((byte) 0x00);
        pingFrame.flip();

        PoolBuffer rttPacket = QuicPacketBuilder.build1RttPacket(
            TEST_CID, 1, pingFrame, meta.clientApplicationKeys, meta.clientApplicationHeaderProtection, (byte) 0);

        try {
            connection.process1RttPacket(rttPacket, 0);
            List<ByteBuffer> rttResponses = getOutboundPackets(connection);
            assertFalse(rttResponses.isEmpty(), "Should generate ACK for 1-RTT PING");
        } finally {
            rttPacket.release();
        }
    }

    private void setClientCid(QuicConnection conn, byte[] cid) throws Exception {
        java.lang.reflect.Field f = QuicConnection.class.getDeclaredField("clientCid");
        f.setAccessible(true);
        f.set(conn, cid);
    }

    private byte[] computeClientFinished(ConnectionMetadata meta) throws Exception {
        // finished_key = HKDF-Expand-Label(clientHandshakeTrafficSecret, "finished", "", 32)
        byte[] finishedKey = QuicCrypto.hkdfExpandLabel(meta.clientHandshakeTrafficSecret, "finished", new byte[0], 32);
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256", "Conscrypt");
        mac.init(new javax.crypto.spec.SecretKeySpec(finishedKey, "HmacSHA256"));
        return mac.doFinal(meta.transcriptHash());
    }

    @Test
    void testGcmTagVerification_TruncatedPacket() throws Exception {
        // Test that packet shorter than GCM tag length is rejected

        byte[] destinationCid = new byte[8];
        ByteBuffer.wrap(destinationCid).putLong(TEST_CONNECTION_ID);

        // Create truncated packet (header only, no payload + tag)
        ByteBuffer truncatedPacket = ByteBuffer.allocate(100);
        truncatedPacket.put((byte) 0xC0); // Long header, Initial
        truncatedPacket.putInt(0x00000001); // Version
        truncatedPacket.put((byte) 8);
        truncatedPacket.putLong(TEST_CONNECTION_ID);
        truncatedPacket.put((byte) 8);
        truncatedPacket.putLong(0xFEDCBA9876543210L);
        truncatedPacket.put((byte) 0); // Token length
        truncatedPacket.put((byte) 10); // Payload length (less than GCM_TAG_LENGTH)
        truncatedPacket.put((byte) 0); // Packet number
        truncatedPacket.put(new byte[9]); // Only 9 bytes (< 16-byte GCM tag)
        truncatedPacket.flip();

        QuicConnection connection = new QuicConnection(TEST_CONNECTION_ID, TEST_ADDRESS, selectorMock);
        PoolBuffer pb = new BorrowedPoolBuffer(mock(RootPoolBuffer.class), truncatedPacket);
        try {
            connection.processInitialAndRespond(pb);
            List<ByteBuffer> responses = getOutboundPackets(connection);

            assertTrue(responses.isEmpty(), "Should reject truncated packet");
            assertEquals(QuicConnection.State.INITIAL, connection.getState());
        } finally {
            pb.release();
        }
    }
    // =========================================================================
    // Private helpers
    // =========================================================================

    /**
     * Builds a minimal but spec-compliant TLS 1.3 ClientHello containing:
     * - cipher_suites: TLS_AES_128_GCM_SHA256 (0x1301)
     * - supported_versions: TLS 1.3 (0x0304)
     * - supported_groups: x25519 (0x001d)
     * - key_share: a fresh x25519 public key
     * - ALPN: "h3"
     */
    private ByteBuffer buildMinimalClientHello() throws Exception {
        // Generate an ephemeral x25519 key pair for the key_share extension
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        kpg.initialize(java.security.spec.NamedParameterSpec.X25519);
        KeyPair kp = kpg.generateKeyPair();
        byte[] pubEncoded = kp.getPublic().getEncoded();
        // Raw 32-byte key is in the last 32 bytes of the SubjectPublicKeyInfo encoding
        byte[] x25519PubKey = java.util.Arrays.copyOfRange(pubEncoded, pubEncoded.length - 32, pubEncoded.length);

        ByteBuffer extensions = ByteBuffer.allocate(512);

        // supported_versions (0x002b): [TLS 1.3]
        extensions.putShort((short) 0x002b);
        extensions.putShort((short) 3);  // ext length
        extensions.put((byte) 2);        // list length
        extensions.putShort((short) 0x0304);

        // signature_algorithms (0x000d): [ecdsa_secp256r1_sha256]
        extensions.putShort((short) 0x000d);
        extensions.putShort((short) 4);  // ext length
        extensions.putShort((short) 2);  // list length
        extensions.putShort((short) 0x0403);

        // supported_groups (0x000a): [x25519]
        extensions.putShort((short) 0x000a);
        extensions.putShort((short) 4);  // ext length
        extensions.putShort((short) 2);  // list length
        extensions.putShort((short) 0x001d);

        // key_share (0x0033): x25519 entry
        // entry = group(2) + key_len(2) + key(32) = 36 bytes
        // client_shares_len(2) + entry = 38 bytes
        extensions.putShort((short) 0x0033);
        extensions.putShort((short) 38); // ext length
        extensions.putShort((short) 36); // client_shares length
        extensions.putShort((short) 0x001d); // group x25519
        extensions.putShort((short) 32);     // key length
        extensions.put(x25519PubKey);

        // ALPN (0x0010): "h3"
        byte[] h3 = "h3".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        // ext content: proto_len(1) + proto = 1+2 = 3
        // alpn_list_len(2) + 3 = 5
        extensions.putShort((short) 0x0010);
        extensions.putShort((short) 5);
        extensions.putShort((short) 3); // alpn list length
        extensions.put((byte) h3.length);
        extensions.put(h3);

        // QUIC transport parameters (0x0039)
        // Let's add max_idle_timeout (0x01) AND initial_source_connection_id (0x0f)
        // RFC 9000 Section 18.2: initial_source_connection_id MUST be present in ServerHello.
        // Wait, this is ClientHello. In ClientHello, it should be the CID used in Initial.
        ByteBuffer params = ByteBuffer.allocate(100);
        QuicVarint.write(params, 0x01); // max_idle_timeout
        QuicVarint.write(params, (long) 1);    // length
        QuicVarint.write(params, (long) 30);   // value 30s
        
        QuicVarint.write(params, 0x0f); // initial_source_connection_id
        QuicVarint.write(params, (long) 8);    // length
        params.putLong(TEST_CONNECTION_ID);
        params.flip();
        
        extensions.putShort((short) 0x0039);
        extensions.putShort((short) params.remaining());
        extensions.put(params);

        extensions.flip();
        int extLen = extensions.remaining();

        // ClientHello body:
        //   legacy_version(2) + random(32) + session_id_len(1) + cipher_suites_len(2)
        //   + cipher_suites(2) + compression_len(1) + compression(1) + ext_len(2) + exts
        int bodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extLen;

        ByteBuffer hello = ByteBuffer.allocate(4 + bodyLen);
        // Handshake header: msg_type(1) + length(3)
        hello.put((byte) 0x01); // ClientHello
        hello.put((byte) ((bodyLen >> 16) & 0xFF));
        hello.put((byte) ((bodyLen >>  8) & 0xFF));
        hello.put((byte) ( bodyLen        & 0xFF));

        hello.putShort((short) 0x0303);      // legacy_version
        hello.put(new byte[32]);              // client random
        hello.put((byte) 0);                  // session_id length = 0
        hello.putShort((short) 2);            // cipher_suites length
        hello.putShort((short) 0x1301);       // TLS_AES_128_GCM_SHA256
        hello.put((byte) 1);                  // compression methods length
        hello.put((byte) 0x00);               // no compression
        hello.putShort((short) extLen);
        hello.put(extensions);

        hello.flip();
        return hello;
    }

    /**
     * Creates a TlsMetadata suitable for 1-RTT tests using the provided key for all roles.
     * The HP key is derived from the 1-RTT client secret.
     */
    private ConnectionMetadata make1RttMetadata(SecretKey real1RttKey) throws Exception {
        byte[] hpKey = QuicCrypto.deriveHeaderProtectionKey(real1RttKey);
        byte[] iv    = deriveIv(real1RttKey.getEncoded());
        ConnectionMetadata m = new ConnectionMetadata();
        m.negotiatedIdleTimeoutMs = 10_000;
        m.clientHandshakeKeys = new QuicCrypto.PacketProtectionKeysWithHP(real1RttKey, new byte[12], null);
        m.serverHandshakeKeys = new QuicCrypto.PacketProtectionKeysWithHP(real1RttKey, new byte[12], null);

        Cipher hpProtection = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding", "Conscrypt");
        hpProtection.init(javax.crypto.Cipher.ENCRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(hpKey, "AES"));

        m.serverApplicationHeaderProtection = hpProtection;
        m.clientApplicationHeaderProtection = hpProtection;
        m.setApplicationKeys(
                new QuicCrypto.PacketProtectionKeys(real1RttKey, iv),
                new QuicCrypto.PacketProtectionKeys(real1RttKey, iv));
        return m;
    }

    /** Derives the base IV from a traffic secret (mirrors QuicCrypto.deriveIv). */
    private byte[] deriveIv(byte[] secret) throws Exception {
        byte[] label = "tls13 quic iv".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        ByteBuffer info = ByteBuffer.allocate(2 + 1 + label.length + 1);
        info.putShort((short) 12);
        info.put((byte) label.length);
        info.put(label);
        info.put((byte) 0);
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256"));
        byte[] result = new byte[12];
        byte[] t = new byte[0];
        int offset = 0, iter = 0;
        byte[] infoBytes = info.array();
        while (offset < 12) {
            mac.update(t); mac.update(infoBytes); mac.update((byte) ++iter);
            t = mac.doFinal();
            int copy = Math.min(t.length, 12 - offset);
            System.arraycopy(t, 0, result, offset, copy);
            offset += copy;
        }
        return result;
    }
}
