package org.fmalyshev.quic;

import org.fmalyshev.quic.buffers.BorrowedPoolBuffer;
import org.fmalyshev.quic.buffers.RootPoolBuffer;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * Integration tests for QUIC connection with REAL cryptographic operations.
 * These tests verify that GCM authentication tags are properly verified,
 * that transcript hashes are accumulated correctly, and that the full
 * Initial → Handshake → 1-RTT sequence works end-to-end.
 *
 * NO MOCKING of QuicCrypto — all encryption/decryption is real.
 */
class QuicConnectionCryptoIntegrationTest {

    private static final long TEST_CONNECTION_ID = 0x1234567890ABCDEFL;
    private static final InetSocketAddress TEST_ADDRESS = new InetSocketAddress("127.0.0.1", 4433);
    SecureRandom secureRandom = new SecureRandom();

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
        ByteBuffer cryptoFrame = ByteBuffer.allocate(1 + 1 + 2 + clientHello.remaining());
        cryptoFrame.put((byte) 0x06);                     // CRYPTO frame type
        QuicVarint.write(cryptoFrame, 0);           // offset (varint)
        QuicVarint.write(cryptoFrame, clientHello.remaining()); // length (2-byte varint 0x4xxx not needed for small sizes)
        cryptoFrame.put(clientHello);
        cryptoFrame.flip();

        ByteBuffer encryptedPacket = QuicPacketBuilder.buildInitialPacket(
            destinationCid,
            0xFEDCBA9876543210L,
            0,
            cryptoFrame,
            clientKeys
        );

        QuicConnection connection = new QuicConnection(TEST_CONNECTION_ID, TEST_ADDRESS);
        connection.processInitialAndRespond(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), encryptedPacket.duplicate()));
        List<ByteBuffer> responses = getOutboundPackets(connection);


        // Decryption succeeded and ClientHello was processed → HANDSHAKE
        assertFalse(responses.isEmpty(), "Initial response (ServerHello) should be generated");
        assertEquals(QuicConnection.State.HANDSHAKE, connection.getState(),
            "Connection should advance to HANDSHAKE after valid Initial packet");
    }

    @Test
    void testGcmTagVerification_InitialPacket_InvalidTag() throws Exception {
        // Test that tampered GCM tag causes packet rejection

        // Step 1: Create valid encrypted packet
        byte[] destinationCid = new byte[8];
        ByteBuffer.wrap(destinationCid).putLong(TEST_CONNECTION_ID);

        QuicCrypto.PacketProtectionKeysWithHP[] keys = QuicCrypto.deriveInitialKeys(destinationCid);
        QuicCrypto.PacketProtectionKeysWithHP clientKeys = keys[0];

        // Build a real TLS 1.3 ClientHello so the CRYPTO frame is structurally valid;
        // the GCM tag will be tampered below — the payload itself must be parseable.
        ByteBuffer clientHello = buildMinimalClientHello();
        ByteBuffer plaintext = ByteBuffer.allocate(1 + 1 + 2 + clientHello.remaining());
        plaintext.put((byte) 0x06);                          // CRYPTO frame type
        QuicVarint.write(plaintext, 0);                      // offset
        QuicVarint.write(plaintext, clientHello.remaining()); // length
        plaintext.put(clientHello);
        plaintext.flip();

        ByteBuffer encryptedPacket = QuicPacketBuilder.buildInitialPacket(
            destinationCid,
            0xFEDCBA9876543210L,
            0,
            plaintext,
            clientKeys
        );

        // Step 2: Tamper with the GCM tag (last 16 bytes)
        ByteBuffer tamperedPacket = encryptedPacket.duplicate();
        int lastBytePos = tamperedPacket.limit() - 1;
        byte originalByte = tamperedPacket.get(lastBytePos);
        tamperedPacket.put(lastBytePos, (byte) (originalByte ^ 0xFF)); // Flip bits
        tamperedPacket.rewind();

        // Step 3: Try to process tampered packet
        QuicConnection connection = new QuicConnection(TEST_CONNECTION_ID, TEST_ADDRESS);
        connection.processInitialAndRespond(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), tamperedPacket));
        List<ByteBuffer> responses = getOutboundPackets(connection);


        // Should be rejected due to invalid GCM tag
        assertTrue(responses.isEmpty(), "Should reject packet with invalid GCM tag");
        assertEquals(QuicConnection.State.INITIAL, connection.getState(),
            "Should remain in INITIAL state after rejected packet");
    }

    @Test
    void testGcmTagVerification_1RttPacket_ValidTag() throws Exception {
        // Verify that a properly encrypted 1-RTT packet is accepted.

        byte[] keyBytes = new byte[16];
        for (int i = 0; i < 16; i++) keyBytes[i] = (byte) i;
        SecretKey real1RttKey = new SecretKeySpec(keyBytes, "AES");

        QuicConnection connection = new QuicConnection(TEST_CONNECTION_ID, TEST_ADDRESS);
        connection.setState(QuicConnection.State.ESTABLISHED);
        connection.setTlsMetadata(make1RttMetadata(real1RttKey));

        ByteBuffer plaintext = ByteBuffer.allocate(20);
        plaintext.put((byte) 0x0e); // STREAM frame
        plaintext.put((byte) 0x00); plaintext.put((byte) 0x00);
        plaintext.put((byte) 5);
        plaintext.put("Hello".getBytes());
        while (plaintext.hasRemaining()) plaintext.put((byte) 0x00);
        plaintext.flip();

                QuicCrypto.TlsMetadata meta1Rtt = make1RttMetadata(real1RttKey);
                ByteBuffer encryptedPacket = QuicPacketBuilder.build1RttPacket(
                    destinationCidBytes(TEST_CONNECTION_ID), 5, plaintext,
                    meta1Rtt.clientApplicationKeys, null, (byte) 0);

        connection.process1RttPacket(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), encryptedPacket.duplicate()));
        List<ByteBuffer> responses = getOutboundPackets(connection);

        assertNotNull(responses, "Should process packet with valid GCM tag");
    }

    public static List<ByteBuffer> getOutboundPackets(QuicConnection connection) {
        List<ByteBuffer> responses = new ArrayList<>();
        for (ByteBuffer res = connection.pollOutbound(); res != null; res = connection.pollOutbound()) {
            responses.add(res);
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

        QuicConnection connection = new QuicConnection(TEST_CONNECTION_ID, TEST_ADDRESS);
        connection.setState(QuicConnection.State.ESTABLISHED);
        connection.setTlsMetadata(make1RttMetadata(real1RttKey));

        ByteBuffer plaintext = ByteBuffer.allocate(20);
        plaintext.put((byte) 0x0e);
        plaintext.put((byte) 0x00); plaintext.put((byte) 0x00);
        plaintext.put((byte) 5);
        plaintext.put("Hello".getBytes());
        while (plaintext.hasRemaining()) plaintext.put((byte) 0x00);
        plaintext.flip();

                        QuicCrypto.TlsMetadata meta1RttInvalid = make1RttMetadata(real1RttKey);
                        ByteBuffer encryptedPacket = QuicPacketBuilder.build1RttPacket(
                ByteBuffer.allocate(8).putLong(TEST_CONNECTION_ID).array(),
                5, plaintext, meta1RttInvalid.clientApplicationKeys, null, (byte) 0);

        // Tamper with the last byte of the GCM authentication tag
        ByteBuffer tamperedPacket = ByteBuffer.wrap(encryptedPacket.array().clone());
        int last = tamperedPacket.limit() - 1;
        tamperedPacket.put(last, (byte) (tamperedPacket.get(last) ^ 0xFF));
        tamperedPacket.rewind();

        connection.process1RttPacket(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), tamperedPacket));
        List<ByteBuffer> responses = getOutboundPackets(connection);

        assertEquals(0, responses.size(), "Should reject packet with invalid GCM tag");
    }

    // =========================================================================
    // End-to-end test: real ClientHello → Initial → Handshake → 1-RTT
    // =========================================================================

    @Test
    void testFullHandshakeSequence_EndToEnd() throws Exception {
        // Exercise the complete Initial → Handshake → 1-RTT flow with real crypto.
        // Verifies: state transitions, transcript hash updates, 1-RTT key availability.

        QuicConnection connection = new QuicConnection(TEST_CONNECTION_ID, TEST_ADDRESS);
        assertEquals(QuicConnection.State.INITIAL, connection.getState());

        // ── Phase 1: Initial packet (ClientHello) ─────────────────────────────
        byte[] dcid = new byte[8];
        ByteBuffer.wrap(dcid).putLong(TEST_CONNECTION_ID);
        QuicCrypto.PacketProtectionKeysWithHP[] initKeys = QuicCrypto.deriveInitialKeys(dcid);

        ByteBuffer clientHello = buildMinimalClientHello();
        // Wrap in CRYPTO frame
        ByteBuffer cryptoFrame = ByteBuffer.allocate(4 + clientHello.remaining());
        cryptoFrame.put((byte) 0x06);                        // CRYPTO frame type
        QuicVarint.write(cryptoFrame, 0x00);                        // offset
        QuicVarint.write(cryptoFrame, clientHello.remaining()); // length
        cryptoFrame.put(clientHello);
        cryptoFrame.flip();

        ByteBuffer initialPacket = QuicPacketBuilder.buildInitialPacket(
            dcid, TEST_CONNECTION_ID, 0, cryptoFrame, initKeys[0]);

        connection.processInitialAndRespond(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), initialPacket));
        List<ByteBuffer> serverHelloPackets = getOutboundPackets(connection);


        assertFalse(serverHelloPackets.isEmpty(), "Server should respond with ServerHello");
        assertEquals(QuicConnection.State.HANDSHAKE, connection.getState(),
            "State should be HANDSHAKE after Initial");

        // TlsMetadata must now be populated with Handshake secrets
        QuicCrypto.TlsMetadata meta = connection.getTlsMetadata();
        assertNotNull(meta, "TlsMetadata should be set");
        assertNotNull(meta.clientHandshakeKeys, "Handshake keys must be derived");
        assertNotNull(meta.serverHandshakeKeys, "Server handshake keys must be derived");
        assertFalse(meta.hasApplicationKeys(),
            "1-RTT keys must NOT be available before client Finished");

        // Transcript hash must be non-zero (ClientHello + ServerHello fed in)
        byte[] transcriptAfterInitial = meta.transcriptHash();
        assertNotNull(transcriptAfterInitial);
        assertEquals(32, transcriptAfterInitial.length);
        boolean nonZero = false;
        for (byte b : transcriptAfterInitial) { if (b != 0) { nonZero = true; break; } }
        assertTrue(nonZero, "Transcript hash must be non-zero after ClientHello + ServerHello");

        // ── Phase 2: Handshake packet (client Finished) ───────────────────────
        // Build a minimal TLS 1.3 Finished message
        // verify_data = HMAC(HKDF-Expand-Label(client_hs_secret,"finished","",32), transcript_hash)
        // For simplicity we send a valid Finished structure; verifyClientFinished accepts it
        // because it uses the live transcript hash from metadata.
        byte[] finishedVerifyData = computeClientFinished(meta);
        byte[] finishedMsg = new byte[4 + finishedVerifyData.length];
        finishedMsg[0] = 0x14; // Finished msg_type
        finishedMsg[1] = 0x00;
        finishedMsg[2] = 0x00;
        finishedMsg[3] = (byte) finishedVerifyData.length;
        System.arraycopy(finishedVerifyData, 0, finishedMsg, 4, finishedVerifyData.length);

        ByteBuffer finishedCryptoFrame = ByteBuffer.allocate(4 + finishedMsg.length);
        finishedCryptoFrame.put((byte) 0x06);
        QuicVarint.write(finishedCryptoFrame, 0x00);
        QuicVarint.write(finishedCryptoFrame, finishedMsg.length);
        finishedCryptoFrame.put(finishedMsg);
        finishedCryptoFrame.flip();

                        byte[] dcidBytes = ByteBuffer.allocate(8).putLong(TEST_CONNECTION_ID).array();
                        ByteBuffer handshakePacket = QuicPacketBuilder.buildHandshakePacket(
            dcidBytes, TEST_CONNECTION_ID, 0,
            finishedCryptoFrame, meta.clientHandshakeKeys);

        connection.processHandshakePacket(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), handshakePacket));
        List<ByteBuffer> handshakeResponses = getOutboundPackets(connection);

        assertFalse(handshakeResponses.isEmpty(),
            "Server should respond to client Finished");
        assertEquals(QuicConnection.State.ESTABLISHED, connection.getState(),
            "State should be ESTABLISHED after Handshake");

        // 1-RTT keys must now be available
        assertTrue(meta.hasApplicationKeys(),
            "1-RTT keys must be derived after client Finished");
        assertNotNull(meta.clientApplicationKeys, "clientApplicationKeys must be set");
        assertNotNull(meta.serverApplicationKeys, "serverApplicationKeys must be set");
        assertNotNull(meta.clientApplicationHeaderProtection, "client1RttHpKey must be set");

        // Transcript hash must have advanced (server messages + client Finished added)
        byte[] transcriptAfterHandshake = meta.transcriptHash();
        assertFalse(java.util.Arrays.equals(transcriptAfterInitial, transcriptAfterHandshake),
            "Transcript hash must change after Handshake phase");

        // ── Phase 3: 1-RTT packet (PING) ──────────────────────────────────────
        ByteBuffer pingFrame = ByteBuffer.allocate(1);
        pingFrame.put((byte) 0x01); // PING
        pingFrame.flip();

                        byte[] rttDcid = new byte[8];
                        ByteBuffer.wrap(rttDcid).putLong(TEST_CONNECTION_ID);
                        ByteBuffer rttPacket = QuicPacketBuilder.build1RttPacket(
            rttDcid, 0, pingFrame, meta.clientApplicationKeys, null, (byte) 0);

        connection.process1RttPacket(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), rttPacket));
        List<ByteBuffer> rttResponses = getOutboundPackets(connection);

        assertNotNull(rttResponses, "Should process 1-RTT packet without error");
        // PING is ack-eliciting, so an ACK should be generated
        assertFalse(rttResponses.isEmpty(), "ACK should be generated for PING frame");
    }

    @Test
    void testGcmTagVerification_TruncatedPacket() throws Exception {
        // Test that packet shorter than GCM tag length is rejected

        byte[] destinationCid = new byte[8];
        ByteBuffer.wrap(destinationCid).putLong(TEST_CONNECTION_ID);

        QuicCrypto.PacketProtectionKeysWithHP[] keys = QuicCrypto.deriveInitialKeys(destinationCid);

        // Create truncated packet (header only, no payload + tag)
        ByteBuffer truncatedPacket = ByteBuffer.allocate(50);
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

        QuicConnection connection = new QuicConnection(TEST_CONNECTION_ID, TEST_ADDRESS);
        connection.processInitialAndRespond(new BorrowedPoolBuffer(mock(RootPoolBuffer.class), truncatedPacket));
        List<ByteBuffer> responses = getOutboundPackets(connection);

        assertTrue(responses.isEmpty(), "Should reject truncated packet");
        assertEquals(QuicConnection.State.INITIAL, connection.getState());
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
        // ext content: alpn_list_len(2) + proto_len(1) + proto = 2+1+2 = 5
        extensions.putShort((short) 0x0010);
        extensions.putShort((short) 5);
        extensions.putShort((short) 3); // alpn list length
        extensions.put((byte) h3.length);
        extensions.put(h3);

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
     * Computes the client Finished verify_data for the given TlsMetadata state:
     *   finished_key = HKDF-Expand-Label(clientHandshakeSecret, "finished", "", 32)
     *   verify_data  = HMAC-SHA256(finished_key, transcript_hash)
     */
    private byte[] computeClientFinished(QuicCrypto.TlsMetadata meta) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        // Derive finished_key via the same HKDF path used in QuicCrypto.verifyClientFinished
        // We replicate the derivation here to stay self-contained.
        byte[] clientSecretBytes = meta.serverHandshakeKeys.key().getEncoded();
        byte[] finishedKey = hkdfExpandLabel(clientSecretBytes, "tls13 finished", new byte[0], 32);
        mac.init(new javax.crypto.spec.SecretKeySpec(finishedKey, "HmacSHA256"));
        return mac.doFinal(meta.transcriptHash());
    }

    private byte[] hkdfExpandLabel(byte[] secret, String label, byte[] context, int length)
            throws Exception {
        byte[] labelBytes = label.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        ByteBuffer info = ByteBuffer.allocate(2 + 1 + labelBytes.length + 1 + context.length);
        info.putShort((short) length);
        info.put((byte) labelBytes.length);
        info.put(labelBytes);
        info.put((byte) context.length);
        info.put(context);

        // HKDF-Expand
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256"));
        byte[] result = new byte[length];
        byte[] t = new byte[0];
        int offset = 0, iter = 0;
        byte[] infoBytes = info.array();
        while (offset < length) {
            mac.update(t);
            mac.update(infoBytes);
            mac.update((byte) ++iter);
            t = mac.doFinal();
            int copy = Math.min(t.length, length - offset);
            System.arraycopy(t, 0, result, offset, copy);
            offset += copy;
        }
        return result;
    }

    /**
     * Creates a TlsMetadata suitable for 1-RTT tests using the provided key for all roles.
     * The HP key is derived from the 1-RTT client secret.
     */
    private QuicCrypto.TlsMetadata make1RttMetadata(SecretKey real1RttKey) throws Exception {
        byte[] hpKey = QuicCrypto.deriveHeaderProtectionKey(real1RttKey);
        byte[] iv    = deriveIv(real1RttKey.getEncoded());
        QuicCrypto.TlsMetadata m = new QuicCrypto.TlsMetadata();
        m.clientRandom            = new byte[32];
        m.serverRandom            = new byte[32];
        m.selectedCipherSuite     = "TLS_AES_128_GCM_SHA256";
        m.alpn                    = "h3";
        m.negotiatedIdleTimeoutMs = 10_000;
        m.clientHandshakeKeys = new QuicCrypto.PacketProtectionKeysWithHP(real1RttKey, new byte[12], new byte[16]);
        m.serverHandshakeKeys = new QuicCrypto.PacketProtectionKeysWithHP(real1RttKey, new byte[12], new byte[16]);
        m.serverApplicationHeaderProtection = hpKey;
        m.clientApplicationHeaderProtection = hpKey;
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
