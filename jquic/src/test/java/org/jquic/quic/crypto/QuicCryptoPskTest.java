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
package org.jquic.quic.crypto;

import org.jquic.quic.*;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.buffers.SlicingOutputStreamWithAmendments;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;

import static org.jquic.quic.crypto.QuicCrypto.sha256;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SuppressWarnings("ResultOfMethodCallIgnored")
class QuicCryptoPskTest {

    private static MockedStatic<QuicCrypto> quicCryptoMock;
    private static MockedStatic<SessionTicketService> sessionTicketServiceMock;
    private final SelectorThread selectorMock = mock(SelectorThread.class);

    @BeforeAll
    static void setUp() throws Exception {
        quicCryptoMock = mockStatic(QuicCrypto.class, CALLS_REAL_METHODS);
        sessionTicketServiceMock = mockStatic(SessionTicketService.class, CALLS_REAL_METHODS);

        KeystoreManager km = mock(KeystoreManager.class);
        quicCryptoMock.when(QuicCrypto::getKeystoreManager).thenReturn(km);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        PrivateKey privateKey = kpg.generateKeyPair().getPrivate();
        when(km.getPrivateKey()).thenReturn(privateKey);

        byte[] keyBytes = QuicCrypto.sha256(privateKey.getEncoded());
        byte[] stek = QuicCrypto.hkdfExpandLabel(keyBytes, "stek", new byte[0], 32);
        ByteBuffer stekBuf = ByteBuffer.allocateDirect(32);
        stekBuf.put(stek).flip();
        NativeCrypto stekNativeCrypto = new NativeCrypto(new QuicCrypto.PacketProtectionKeysWithHP(stekBuf, null, null), CipherMode.TLS_AES_256_GCM_SHA384_ID);
        sessionTicketServiceMock.when(()-> SessionTicketService.getStekCrypto(any())).thenReturn(stekNativeCrypto);

        byte[] stekUuid = HexFormat.of().parseHex("c50b367e1da534e796ed80ce199f493a");
        SessionTicketService.addStekKey(stekUuid, stek);

        QuicProperties.ENABLE_SESSION_RESUMPTION = true;
    }

    @AfterAll
    static void tearDown() {
        if (quicCryptoMock != null) {
            quicCryptoMock.close();
        }
        if (sessionTicketServiceMock != null) {
            sessionTicketServiceMock.close();
        }
    }

    @Test
    void testParseClientHelloWithPsk() throws Exception {
        System.out.println("[DEBUG_LOG] Starting testParseClientHelloWithPsk");
        // 1. Create a valid session ticket
        byte[] psk = HexFormat.of().parseHex("c50b367e1da534e796ed80ce199f4939230b1f300bc155f1ebd44f41705b8239");

        ConnectionMetadata.ClientMetadataNegotiated metadata = new ConnectionMetadata.ClientMetadataNegotiated(
                "h3", 30000L, List.of((short) 0x001d), new HashMap<>(), 1450L,
                1000000L, 65536L, 65536L, 65536L, 100L, 100L,
                List.of((short) 0x0403), 3L, List.of(0x00000001), CipherMode.TLS_AES_128_GCM_SHA256_ID, null,
                -1);

        ByteBuffer ticketBuf = ByteBuffer.allocateDirect(1024);
        long timestamp = System.currentTimeMillis();
        SessionTicketService.generateSessionTicket(ticketBuf, psk, metadata, 1L, timestamp, 12344523L);
        // generateSessionTicket returns the buffer with position at start and limit at end of ticket
        byte[] ticket = new byte[ticketBuf.remaining()];
        ticketBuf.get(ticket);

        // 2. Build ClientHello with pre_shared_key extension
        // Using a manual approach to build a minimal ClientHello
        ByteBuffer ch = ByteBuffer.allocateDirect(2048);
        ch.put((byte) 0x01); // msg_type: ClientHello
        int lengthPos = ch.position();
        ch.put(new byte[3]); // placeholder for length

        ch.putShort((short) 0x0303); // legacy_version: TLS 1.2
        byte[] clientRandom = new byte[32];
        ch.put(clientRandom);
        ch.put((byte) 0); // legacy_session_id length

        ch.putShort((short) 2); // cipher_suites length
        ch.putShort((short) 0x1301); // TLS_AES_128_GCM_SHA256

        ch.put((byte) 1); // legacy_compression_methods length
        ch.put((byte) 0);

        int extStart = ch.position();
        ch.putShort((short) 0); // placeholder for extensions length

        // supported_versions extension
        ch.putShort((short) 0x002b);
        ch.putShort((short) 3);
        ch.put((byte) 2);
        ch.putShort((short) 0x0304);

        // transport_parameters extension
        ch.putShort((short) 0xffa5);
        int tpStart = ch.position();
        ch.putShort((short) 0); // placeholder for len
        QuicVarint.write(ch, 0x01); // max_idle_timeout
        QuicVarint.write(ch, 1);    // len
        QuicVarint.write(ch, 1);    // value
        int tpLen = ch.position() - tpStart - 2;
        ch.putShort(tpStart, (short) tpLen);

        // pre_shared_key extension
        ch.putShort((short) 0x0029);
        int pskExtLenPos = ch.position();
        ch.putShort((short) 0); // placeholder

        // identities
        int identitiesStart = ch.position();

        ch.putShort((short) 0); // placeholder for identities length
        ch.putShort((short) ticket.length);
        ch.put(ticket);
        ch.putInt( (int)((12344523L) & 0xFFFFFFFFL) ); // obfuscated_ticket_age
        int identitiesLen = ch.position() - identitiesStart - 2;
        ch.putShort(identitiesStart, (short) identitiesLen);

        // binders
        int binderListLenPos = ch.position();
        ch.putShort((short) 33); // binders length (1 byte len + 32 bytes binder)
        ch.put((byte) 32); // binder length
        int binderPos = ch.position();
        ch.put(new byte[32]); // placeholder

        int pskExtLen = ch.position() - pskExtLenPos - 2;
        ch.putShort(pskExtLenPos, (short) pskExtLen);

        // key_share extension
        ch.putShort((short) 0x0033);
        ch.putShort((short) (2 + 2 + 32)); // total length
        ch.putShort((short) (2 + 32)); // length of one key share
        ch.putShort((short) 0x001d); // x25519
        ch.putShort((short) 32);
        
        // Use a valid X25519 public key (point with large order)
        // A simple one is for private key 1: base point G.
        // Or just generate one.
        KeyPairGenerator kpgGen = KeyPairGenerator.getInstance("XDH");
        kpgGen.initialize(new java.security.spec.NamedParameterSpec("X25519"));
        byte[] validPub = kpgGen.generateKeyPair().getPublic().getEncoded();
        // Spki for X25519 is 44 bytes, last 32 are raw key
        ch.put(validPub, validPub.length - 32, 32);

        int extensionsLen = ch.position() - extStart - 2;
        ch.putShort(extStart, (short) extensionsLen);

        int totalLen = ch.position() - 4;
        ch.put(lengthPos, (byte) ((totalLen >> 16) & 0xFF));
        ch.put(lengthPos + 1, (byte) ((totalLen >> 8) & 0xFF));
        ch.put(lengthPos + 2, (byte) (totalLen & 0xFF));


        // Calculate binder
        byte[] earlySecret = QuicCrypto.hkdfExtract(new byte[32], psk);


        byte[] resumptionBinderKey = QuicCrypto.hkdfExpandLabel(earlySecret, "res binder", sha256(new byte[0]), 32);
        byte[] verifier = QuicCrypto.hkdfExpandLabel(resumptionBinderKey, "finished", new byte[0], 32);
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(verifier, "HmacSHA256"));
        ByteBuffer truncated = ch.duplicate();
        truncated.position(0);
        truncated.limit(binderListLenPos);

        byte[] truncatedBytes = new byte[truncated.remaining()];
        truncated.get(truncatedBytes);
        byte[] transcriptHash = QuicCrypto.sha256(truncatedBytes);

        byte[] binder = mac.doFinal(transcriptHash);
        ch.put(binderPos, binder);

        ch.flip();

        // 3. Call parseClientHello
        ConnectionMetadata.ClientMetadataNegotiated result = QuicCrypto.parseClientHello(timestamp, new ConnectionMetadata(), ch);
        // This is expected to succeed and have selectedIdentity = 0 after implementation
        assertEquals(0, result.selectedIdentity);

        // 4. Test processClientHello with PSK
        ConnectionMetadata connMetadata = new ConnectionMetadata();
        connMetadata.quicVersion = org.jquic.quic.QuicVersion.QUIC_VERSION_1;
        ch.position(0);
        
        // Mock getKeystoreManager to return something that won't fail signature scheme selection
        KeystoreManager km = QuicCrypto.getKeystoreManager();
        when(km.selectSignatureScheme(any())).thenReturn((short) 0x0403);
        
        QuicCrypto.processClientHello(timestamp, connMetadata, ch);

        org.junit.jupiter.api.Assertions.assertNotNull(connMetadata.zeroRttCrypto, "0-RTT crypto should be initialized");
        org.junit.jupiter.api.Assertions.assertNotNull(connMetadata.handshakeSecretBytes, "Handshake secret should be derived");
    }

    @Test
    void testWriteServerHelloWithPsk() throws Exception {
        ConnectionMetadata metadata = new ConnectionMetadata();
        metadata.clientMetadata = new ConnectionMetadata.ClientMetadataNegotiated(
                "h3", 30000L, List.of((short) 0x001d), new HashMap<>(), 1450L,
                1000000L, 65536L, 65536L, 65536L, 100L, 100L,
                List.of((short) 0x0403), 3L, List.of(0x00000001), CipherMode.TLS_AES_128_GCM_SHA256_ID, null,
                0); // Selected identity 0

        metadata.serverEphemeralPublicKey = new byte[32];
        metadata.selectedKeyScheme = 0x001d;

        PoolBuffer pbuf = mock(PoolBuffer.class);
        ByteBuffer directBuf = ByteBuffer.allocateDirect(1024);
        when(pbuf.buf()).thenReturn(directBuf);

        SlicingOutputStreamWithAmendments out = new SlicingOutputStreamWithAmendments(pbuf, 1024, 0, (_) -> 1024, null);

        QuicFrameBuilder.writeServerHello(out, metadata);

        directBuf.flip();

        // ServerHello header
        assertEquals((byte) 0x02, directBuf.get()); // msg_type
        int length = ((directBuf.get() & 0xFF) << 16) | ((directBuf.get() & 0xFF) << 8) | (directBuf.get() & 0xFF);
        assertEquals(directBuf.remaining(), length);

        directBuf.getShort(); // legacy_version
        directBuf.position(directBuf.position() + 32); // random
        int sessionIdLen = directBuf.get() & 0xFF;
        directBuf.position(directBuf.position() + sessionIdLen);
        directBuf.getShort(); // cipher_suite
        directBuf.get(); // compression

        int extensionsLenBytes = directBuf.getShort() & 0xFFFF;
        int extensionsEnd = directBuf.position() + extensionsLenBytes;

        boolean pskFound = false;
        while (directBuf.position() < extensionsEnd) {
            int type = directBuf.getShort() & 0xFFFF;
            int len = directBuf.getShort() & 0xFFFF;
            if (type == 0x0029) { // pre_shared_key
                pskFound = true;
                assertEquals(2, len);
                assertEquals(0, directBuf.getShort() & 0xFFFF);
            } else {
                directBuf.position(directBuf.position() + len);
            }
        }
        org.junit.jupiter.api.Assertions.assertTrue(pskFound, "pre_shared_key extension not found in ServerHello");
    }

    @Test
    void testSendHandshakePacketWithPsk() throws Exception {
        // Mock certChainBytes to avoid NPE in sendHandshakePacket
        java.lang.reflect.Field certChainField = QuicCrypto.class.getDeclaredField("certChainBytes");
        certChainField.setAccessible(true);
        byte[] originalCertChain = (byte[]) certChainField.get(null);
        certChainField.set(null, new byte[0]);

        try {
            // Setup metadata for resumption
            ConnectionMetadata metadata = new ConnectionMetadata();
            metadata.clientMetadata = new ConnectionMetadata.ClientMetadataNegotiated(
                    "h3", 30000L, List.of((short) 0x001d), new HashMap<>(), 1450L,
                    1000000L, 65536L, 65536L, 65536L, 100L, 100L,
                    List.of((short) 0x0403), 3L, List.of(0x00000001), CipherMode.TLS_AES_128_GCM_SHA256_ID, null,
                    0); // Selected identity 0
            metadata.handshakeSecretBytes = new byte[32];
            metadata.clientHandshakeTrafficSecret = new byte[32];
            metadata.serverHandshakeTrafficSecret = new byte[32];
            metadata.clientHandshakeCrypto = mock(NativeCrypto.class);
            metadata.serverHandshakeCrypto = mock(NativeCrypto.class);

            // Setup QuicConnection
            org.jquic.quic.buffers.BufferPool pool = new org.jquic.quic.buffers.BufferPool();
            when(selectorMock.getBufferPool()).thenReturn(pool);

            QuicConnection connection = new QuicConnection(1L, QuicVersion.QUIC_VERSION_1,
                    new InetSocketAddress("127.0.0.1", 1234), selectorMock, new byte[8]);
            
            // Inject metadata
            java.lang.reflect.Field metaField = QuicConnection.class.getDeclaredField("connectionMetadata");
            metaField.setAccessible(true);
            metaField.set(connection, metadata);

            // Capture calls to QuicCrypto.putCertificate and putCertificateVerify
            // These are already mocked via quicCryptoMock.
            // We need to verify they are NOT called when sendHandshakePacket is executed.
            
            // Before calling, reset mocks to clear any previous interactions
            quicCryptoMock.when(() -> QuicCrypto.putEncryptedExtensions(any(), anyLong(), any(), any())).thenAnswer(_ -> null);
            quicCryptoMock.when(() -> QuicCrypto.putCertificate(any())).thenAnswer(_ -> null);
            quicCryptoMock.when(() -> QuicCrypto.putCertificateVerify(any(), any())).thenAnswer(_ -> null);
            quicCryptoMock.when(() -> QuicCrypto.createServerFinished(any(), any())).thenAnswer(_ -> null);

            // Act
            java.lang.reflect.Method method = QuicConnection.class.getDeclaredMethod("sendHandshakePacket");
            method.setAccessible(true);
            method.invoke(connection);

            // Assert
            quicCryptoMock.verify(() -> QuicCrypto.putEncryptedExtensions(any(), anyLong(), any(), any()), times(1));
            quicCryptoMock.verify(() -> QuicCrypto.putCertificate(any()), times(0));
            quicCryptoMock.verify(() -> QuicCrypto.putCertificateVerify(any(), any()), times(0));
            quicCryptoMock.verify(() -> QuicCrypto.createServerFinished(any(), any()), times(1));
        } finally {
            certChainField.set(null, originalCertChain);
        }
    }
}
