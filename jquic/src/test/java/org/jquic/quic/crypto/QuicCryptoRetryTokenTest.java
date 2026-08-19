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

import org.jquic.quic.KeystoreManager;
import org.jquic.quic.QuicException;
import org.jquic.quic.QuicTransportError;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class QuicCryptoRetryTokenTest {

    private static MockedStatic<QuicCrypto> quicCryptoMock;
    private static NativeCrypto nativeCrypto;

    @BeforeAll
    static void setUp() throws Exception {
        quicCryptoMock = mockStatic(QuicCrypto.class, CALLS_REAL_METHODS);
        KeystoreManager km = mock(KeystoreManager.class);
        quicCryptoMock.when(QuicCrypto::getKeystoreManager).thenReturn(km);


        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        PrivateKey privateKey = kpg.generateKeyPair().getPrivate();
        when(km.getPrivateKey()).thenReturn(privateKey);

        byte[] keyBytes = QuicCrypto.sha256(privateKey.getEncoded());
        byte[] retryTokenKey = Arrays.copyOf(keyBytes, 16);

        ByteBuffer retryTokenKeyBuf = ByteBuffer.allocateDirect(16);
        retryTokenKeyBuf.put(retryTokenKey).flip();
        quicCryptoMock.when(QuicCrypto::retryTokenKeyBuf).thenReturn(retryTokenKeyBuf);

        nativeCrypto = QuicCrypto.getRetryTokenCrypto();
    }

    @AfterAll
    static void tearDown() throws Exception {
        if (quicCryptoMock != null) {
            quicCryptoMock.close();
        }
        if (nativeCrypto != null) {
            nativeCrypto.close();
        }
    }

    @Test
    void testRetryTokenIPv4() throws Exception {
        long timestamp = System.currentTimeMillis();
        byte[] cid = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        InetSocketAddress address = new InetSocketAddress("127.0.0.1", 12345);
        ByteBuffer buffer = ByteBuffer.allocateDirect(100);

        buffer.position(10); //Start at non-zero position

        int length = QuicCrypto.generateRetryToken(nativeCrypto, buffer, timestamp, cid, address);
        // IV(12) + Tag(16) + Plaintext(8+1+8+4+2=23) = 51
        assertEquals(51, length);
        assertEquals(length, buffer.remaining());

        QuicCrypto.RetryTokenInfo info = QuicCrypto.parseRetryToken(nativeCrypto, buffer);

        assertEquals(timestamp, info.timestamp());
        assertArrayEquals(cid, info.connectionId());
        assertEquals(address.getAddress(), info.ip());
        assertEquals(address.getPort(), info.port());
    }

    @Test
    void testRetryTokenIPv6() throws Exception {
        long timestamp = System.currentTimeMillis();
        byte[] cid = new byte[]{8, 7, 6, 5, 4, 3, 2, 1};
        InetSocketAddress address = new InetSocketAddress("::1", 54321);
        ByteBuffer buffer = ByteBuffer.allocateDirect(100);

        int length = QuicCrypto.generateRetryToken(nativeCrypto, buffer, timestamp, cid, address);
        // IV(12) + Tag(16) + Plaintext(8+1+8+16+2=35) = 63
        assertEquals(63, length);
        assertEquals(length, buffer.remaining());

        QuicCrypto.RetryTokenInfo info = QuicCrypto.parseRetryToken(nativeCrypto, buffer);

        assertEquals(timestamp, info.timestamp());
        assertArrayEquals(cid, info.connectionId());
        assertEquals(address.getAddress(), info.ip());
        assertEquals(address.getPort(), info.port());
    }

    @Test
    void testRetryTokenVariableCID() throws Exception {
        long timestamp = System.currentTimeMillis();
        InetSocketAddress address = new InetSocketAddress("127.0.0.1", 12345);
        ByteBuffer buffer = ByteBuffer.allocateDirect(100);

        // Min length CID (1 byte)
        byte[] cid1 = new byte[]{0x42};
        int length1 = QuicCrypto.generateRetryToken(nativeCrypto, buffer.clear(), timestamp, cid1, address);
        // IV(12) + Tag(16) + Plaintext(8+1+1+4+2=16) = 44
        assertEquals(44, length1);
        QuicCrypto.RetryTokenInfo info1 = QuicCrypto.parseRetryToken(nativeCrypto, buffer);
        assertArrayEquals(cid1, info1.connectionId());

        // Max length CID (20 bytes)
        byte[] cid20 = new byte[20];
        for (int i = 0; i < 20; i++) cid20[i] = (byte) i;
        int length20 = QuicCrypto.generateRetryToken(nativeCrypto, buffer.clear(), timestamp, cid20, address);
        // IV(12) + Tag(16) + Plaintext(8+1+20+4+2=35) = 63
        assertEquals(63, length20);
        QuicCrypto.RetryTokenInfo info20 = QuicCrypto.parseRetryToken(nativeCrypto, buffer);
        assertArrayEquals(cid20, info20.connectionId());
    }

    @Test
    void testRetryTokenInvalidCIDLength() {
        long timestamp = System.currentTimeMillis();
        InetSocketAddress address = new InetSocketAddress("127.0.0.1", 12345);
        ByteBuffer buffer = ByteBuffer.allocateDirect(100);

        // CID too long (21 bytes)
        byte[] cid21 = new byte[21];
        assertThrows(QuicException.class, () ->
                QuicCrypto.generateRetryToken(nativeCrypto, buffer, timestamp, cid21, address));

        // CID too short (0 bytes)
        byte[] cid0 = new byte[0];
        assertThrows(QuicException.class, () ->
                QuicCrypto.generateRetryToken(nativeCrypto, buffer, timestamp, cid0, address));
    }

    @Test
    void testRetryTokenMismatchIP() throws Exception {
        long timestamp = System.currentTimeMillis();
        byte[] cid = new byte[8];
        InetSocketAddress address = new InetSocketAddress("127.0.0.1", 12345);
        InetSocketAddress wrongAddress = new InetSocketAddress("127.0.0.2", 12345);
        ByteBuffer buffer = ByteBuffer.allocateDirect(100);

        QuicCrypto.generateRetryToken(nativeCrypto, buffer, timestamp, cid, address);

        QuicCrypto.RetryTokenInfo retryTokenInfo = QuicCrypto.parseRetryToken(nativeCrypto, buffer);

        assertNotEquals(retryTokenInfo.ip(), wrongAddress.getAddress());
        assertEquals(retryTokenInfo.ip(), address.getAddress());
        assertEquals(retryTokenInfo.port(), address.getPort());
    }


    @Test
    void testRetryTokenMismatchPort() throws Exception {
        long timestamp = System.currentTimeMillis();
        byte[] cid = new byte[8];
        InetSocketAddress address = new InetSocketAddress("127.0.0.1", 12345);
        InetSocketAddress wrongAddress = new InetSocketAddress("127.0.0.1", 12346);
        ByteBuffer buffer = ByteBuffer.allocateDirect(100);

        QuicCrypto.generateRetryToken(nativeCrypto, buffer, timestamp, cid, address);

        QuicCrypto.RetryTokenInfo retryTokenInfo = QuicCrypto.parseRetryToken(nativeCrypto, buffer);

        assertNotEquals(retryTokenInfo.port(), wrongAddress.getPort());
        assertEquals(retryTokenInfo.ip(), address.getAddress());
        assertEquals(retryTokenInfo.port(), address.getPort());
    }

    @Test
    void testRetryTokenInvalidData() {
        ByteBuffer buffer = ByteBuffer.allocateDirect(100);
        buffer.put(new byte[50]).flip();

        QuicException ex = assertThrows(QuicException.class, () ->
                QuicCrypto.parseRetryToken(nativeCrypto, buffer));
        assertEquals(QuicTransportError.INVALID_TOKEN, ex.getError());
    }
    @Test
    void testParseRetryTokenLeavesBufferEncrypted() throws Exception {
        long timestamp = System.currentTimeMillis();
        byte[] cid = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        InetSocketAddress address = new InetSocketAddress("127.0.0.1", 12345);
        ByteBuffer buffer = ByteBuffer.allocateDirect(100);

        int length = QuicCrypto.generateRetryToken(nativeCrypto, buffer, timestamp, cid, address);
        
        // Take a snapshot of the encrypted data (after IV)
        byte[] encryptedSnapshot = new byte[length - QuicCrypto.GCM_NONCE_LENGTH];
        int originalPosition = buffer.position();
        int originalLimit = buffer.limit();
        
        buffer.position(originalPosition + QuicCrypto.GCM_NONCE_LENGTH);
        buffer.get(encryptedSnapshot);
        buffer.position(originalPosition);

        // Parse token
        QuicCrypto.parseRetryToken(nativeCrypto, buffer);

        // Verify that the buffer content (after IV) is the same as before parsing
        byte[] afterParseContent = new byte[encryptedSnapshot.length];
        buffer.position(originalPosition + QuicCrypto.GCM_NONCE_LENGTH);
        buffer.get(afterParseContent);
        
        assertArrayEquals(encryptedSnapshot, afterParseContent, "Buffer should be re-encrypted after parsing");
        buffer.position(originalPosition);
        assertEquals(originalPosition, buffer.position(), "Position should be restored");
        assertEquals(originalLimit, buffer.limit(), "Limit should be restored");
    }
}
