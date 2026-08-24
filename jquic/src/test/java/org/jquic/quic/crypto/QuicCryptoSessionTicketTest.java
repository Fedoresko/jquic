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

import org.jquic.quic.ConnectionMetadata;
import org.jquic.quic.KeystoreManager;
import org.jquic.quic.buffers.TestPoolBuffer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.List;

import static org.jquic.quic.crypto.QuicCrypto.hkdfExpandLabel;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SuppressWarnings("ResultOfMethodCallIgnored")
class QuicCryptoSessionTicketTest {

    private static MockedStatic<SessionTicketService> sessionTicketServiceMock;
    private static MockedStatic<QuicCrypto> quicCryptoMock;

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
        byte[] stek = hkdfExpandLabel(keyBytes, "stek", new byte[0], 32);
        ByteBuffer stekBuf = ByteBuffer.allocateDirect(32);
        stekBuf.put(stek).flip();
        NativeCrypto stekNativeCrypto = new NativeCrypto(new QuicCrypto.PacketProtectionKeysWithHP(stekBuf, null, null), CipherMode.TLS_AES_256_GCM_SHA384_ID);

        sessionTicketServiceMock.when(() -> SessionTicketService.getStekCrypto(any())).thenReturn(stekNativeCrypto);

        byte[] stekUuid = new byte[16];
        QuicCrypto.secureRandom.get().nextBytes(stekUuid);
        SessionTicketService.addStekKey(stekUuid, stek);
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
    void testSessionTicketRoundTrip() throws Exception {
        byte[] psk = new byte[32];
        QuicCrypto.secureRandom.get().nextBytes(psk);

        List<Short> groups = List.of((short) 0x001d, (short) 0x0017);
        List<Short> sigs = List.of((short) 0x0403, (short) 0x0804);
        List<Integer> versions = List.of(0x00000001);

        ConnectionMetadata.ClientMetadataNegotiated metadata = new ConnectionMetadata.ClientMetadataNegotiated(
                "h3", 30000L, groups, new HashMap<>(), 1450L,
                1000000L, 65536L, 65536L, 65536L, 100L, 100L,
                sigs, 3L, versions, CipherMode.TLS_AES_128_GCM_SHA256_ID, null,
                -1);
        metadata.maxIdleTimeoutMs = 15000L;

        long uniqueNumber = 123456789L;
        long timestamp = System.currentTimeMillis();
        long ticketAgeAdd = 987654321L;

        ByteBuffer output = ByteBuffer.allocateDirect(4048);
        SessionTicketService.generateSessionTicket(output, psk, metadata, uniqueNumber, timestamp, ticketAgeAdd);

        assertTrue(output.remaining() > 0);

        SessionTicketService.SessionTicketInfo info = SessionTicketService.parseSessionTicket(output);

        assertArrayEquals(psk, info.psk());
        assertEquals(uniqueNumber, info.uniqueNumber());
        assertEquals(timestamp, info.timestamp());
        assertEquals(ticketAgeAdd, info.ticketAgeAdd());

        ConnectionMetadata.ClientMetadataNegotiated decMetadata = info.metadata();
        assertEquals(metadata.alpn, decMetadata.alpn);
        assertEquals(metadata.maxIdleTimeoutMs, decMetadata.maxIdleTimeoutMs);
        assertEquals(metadata.maxUdpPayloadSize, decMetadata.maxUdpPayloadSize);
        assertEquals(metadata.initialStreamLimits.maxData, decMetadata.initialStreamLimits.maxData);
        assertEquals(metadata.supportedGroups, decMetadata.supportedGroups);
        assertEquals(metadata.supportedSignatures, decMetadata.supportedSignatures);
        assertEquals(metadata.selectedCipherSuite, decMetadata.selectedCipherSuite);
        assertEquals(metadata.availableVersions, decMetadata.availableVersions);
    }

    @Test
    void testCreateNewSessionTicket() throws Exception {
        byte[] rms = new byte[32];
        QuicCrypto.secureRandom.get().nextBytes(rms);

        List<Short> groups = List.of((short) 0x001d);
        List<Short> sigs = List.of((short) 0x0403);
        List<Integer> versions = List.of(0x00000001);

        ConnectionMetadata.ClientMetadataNegotiated metadata = new ConnectionMetadata.ClientMetadataNegotiated(
                "h3", 30000L, groups, new HashMap<>(), 1450L,
                1000000L, 65536L, 65536L, 65536L, 100L, 100L,
                sigs, 3L, versions, CipherMode.TLS_AES_128_GCM_SHA256_ID, null,
                -1);

        ConnectionMetadata connMetadata = mock(ConnectionMetadata.class);
        connMetadata.resumptionMasterSecret = rms;
        connMetadata.clientMetadata = metadata;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        long timestamp = System.currentTimeMillis();
        SessionTicketService.createNewSessionTicket(sz -> new TestPoolBuffer(ByteBuffer.allocateDirect(sz)), connMetadata, timestamp, dos);
        dos.flush();

        byte[] result = baos.toByteArray();
        assertTrue(result.length > 4);

        ByteBuffer buf = ByteBuffer.wrap(result);
        byte msgType = buf.get();
        assertEquals(0x04, msgType); // HandshakeType: new_session_ticket

        int length = ((buf.get() & 0xFF) << 16) | ((buf.get() & 0xFF) << 8) | (buf.get() & 0xFF);
        assertEquals(result.length - 4, length);

        int lifetime = buf.getInt();
        assertEquals(86400, lifetime);

        int ticketAgeAdd = buf.getInt();

        int nonceLen = buf.get() & 0xFF;
        byte[] nonce = new byte[nonceLen];
        buf.get(nonce);

        int ticketLen = buf.getShort() & 0xFFFF;
        byte[] encryptedTicket = new byte[ticketLen];
        buf.get(encryptedTicket);

        int extensionsLen = buf.getShort() & 0xFFFF;
        assertTrue(extensionsLen >= 8, "Extensions length should be at least 8 (for EARLY_DATA)");

        boolean foundEarlyData = false;
        int extensionsEnd = buf.position() + extensionsLen;
        while (buf.position() < extensionsEnd) {
            int extType = buf.getShort() & 0xFFFF;
            int extLen = buf.getShort() & 0xFFFF;
            if (extType == 42) { // early_data
                assertEquals(4, extLen);
                int maxEarlyDataSize = buf.getInt();
                assertEquals(0xFFFFFFFF, maxEarlyDataSize);
                foundEarlyData = true;
            } else {
                buf.position(buf.position() + extLen);
            }
        }
        assertTrue(foundEarlyData, "EARLY_DATA extension not found");

        // Verify the ticket content
        ByteBuffer directTicket = ByteBuffer.allocateDirect(encryptedTicket.length);
        directTicket.put(encryptedTicket).flip();
        SessionTicketService.SessionTicketInfo info = SessionTicketService.parseSessionTicket(directTicket);
        // RMS in the ticket should be the per-ticket RMS, not the connection RMS
        assertFalse(java.util.Arrays.equals(rms, info.psk()));
        
        // ticketId is now independent and should be recovered from the ticket content
        assertTrue(info.uniqueNumber() != 0);
        assertEquals(timestamp, info.timestamp());
        assertEquals(ticketAgeAdd & 0xFFFFFFFFL, info.ticketAgeAdd());
        assertEquals("h3", info.metadata().alpn);
    }

    @Test
    void testTryParsePreSharedKeyRestoresAllFields() throws Exception {
        byte[] psk = new byte[32];
        QuicCrypto.secureRandom.get().nextBytes(psk);

        ConnectionMetadata.ClientMetadataNegotiated metadata = new ConnectionMetadata.ClientMetadataNegotiated(
                "h3", 30000L, List.of((short) 0x001d), new HashMap<>(), 1450L,
                1000000L, 65536L, 65536L, 65536L, 100L, 100L,
                List.of((short) 0x0403), 3L, List.of(0x00000001), CipherMode.TLS_AES_128_GCM_SHA256_ID, null,
                -1);

        ByteBuffer ticketBuf = ByteBuffer.allocateDirect(4048);
        long ticketAgeAdd = 12345L;
        long timestamp = 67890L;
        SessionTicketService.generateSessionTicket(ticketBuf, psk, metadata, 1L, timestamp, ticketAgeAdd);
        byte[] ticket = new byte[ticketBuf.remaining()];
        ticketBuf.get(ticket);

        // Build PSK extension buffer
        // identities list length (2)
        //   identity length (2)
        //   identity (ticket)
        //   obfuscated_ticket_age (4)
        // binders list length (2)
        //   binder length (1)
        //   binder (32 bytes zero for now, we'll mock verifyBinder or just ignore it if possible)
        
        ByteBuffer pskExt = ByteBuffer.allocate(1024);
        pskExt.putShort((short) (2 + ticket.length + 4)); // identities list len
        pskExt.putShort((short) ticket.length);
        pskExt.put(ticket);
        pskExt.putInt((int) ticketAgeAdd); // obfuscated age (matching exactly for simplicity)
        
        pskExt.putShort((short) 33); // binders list len
        pskExt.put((byte) 32);
        pskExt.put(new byte[32]);
        pskExt.flip();

        ConnectionMetadata connMetadata = new ConnectionMetadata();
        
        // Use the already registered sessionTicketServiceMock
        sessionTicketServiceMock.when(() -> SessionTicketService.getStekCrypto(any())).thenCallRealMethod();
        sessionTicketServiceMock.when(() -> SessionTicketService.parseSessionTicket(any())).thenCallRealMethod();
        sessionTicketServiceMock.when(() -> SessionTicketService.tryParsePreSharedKey(anyLong(), any(), any())).thenCallRealMethod();
        sessionTicketServiceMock.when(() -> SessionTicketService.verifyBinder(any(), any(), any())).thenAnswer(_ -> null);

        ConnectionMetadata.ClientMetadataNegotiated restored = SessionTicketService.tryParsePreSharedKey(timestamp, connMetadata, pskExt);

        assertNotNull(restored);
        assertEquals("h3", restored.alpn);
        assertArrayEquals(psk, restored.psk);
    }
}
