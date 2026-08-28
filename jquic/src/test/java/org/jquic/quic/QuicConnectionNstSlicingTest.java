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

import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.buffers.TestPoolBuffer;
import org.jquic.quic.crypto.CipherMode;
import org.jquic.quic.crypto.NativeCrypto;
import org.jquic.quic.crypto.QuicCrypto;
import org.jquic.quic.crypto.SessionTicketService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class QuicConnectionNstSlicingTest {

    private QuicConnection connection;
    private MockedStatic<QuicCrypto> cryptoMock;
    private MockedStatic<SessionTicketService> sessionTicketServiceMock;
    private MockedStatic<QuicProperties> propertiesMock;
    private ConnectionMetadata mockMetadata;

    @BeforeEach
    void setUp() throws Exception {
        cryptoMock = Mockito.mockStatic(QuicCrypto.class, Answers.CALLS_REAL_METHODS);
        propertiesMock = Mockito.mockStatic(QuicProperties.class, Answers.CALLS_REAL_METHODS);
        sessionTicketServiceMock = Mockito.mockStatic(SessionTicketService.class, Answers.CALLS_REAL_METHODS);
        QuicProperties.ENABLE_SESSION_RESUMPTION = true;

        mockMetadata = new ConnectionMetadata();
        mockMetadata.resumptionMasterSecret = new byte[32];
        mockMetadata.clientMetadata = new ConnectionMetadata.ClientMetadataNegotiated(
                "h3", 30000, new ArrayList<>(), new HashMap<>(), 1200,
                1000000, 65536, 65536, 65536, 100, 100,
                new ArrayList<>(), 3, new ArrayList<>(), CipherMode.TLS_AES_128_GCM_SHA256_ID, new byte[32],
                -1, null);

        SelectorThread selectorMock = mock(SelectorThread.class);
        org.jquic.quic.buffers.BufferPool poolMock = mock(org.jquic.quic.buffers.BufferPool.class);
        when(selectorMock.getBufferPool()).thenReturn(poolMock);
        
        // We need to return a buffer that has space for prependCryptoFrameHeader
        when(poolMock.requestWriteBuffer()).thenAnswer(_ -> {
            ByteBuffer bb = ByteBuffer.allocateDirect(2000);
            bb.position(20); // Give some space for header
            return new TestPoolBuffer(bb).borrow();
        });

        when(poolMock.requestCryptoBuffer(anyInt())).thenAnswer(inv -> {
            int size = inv.getArgument(0);
            ByteBuffer bb = ByteBuffer.allocateDirect(size + 200);
            bb.position(100); // Give some space for header
            return new TestPoolBuffer(bb).borrow();
        });

        cryptoMock.when(() -> QuicCrypto.generateStatelessResetToken(any())).thenReturn(new byte[16]);

        connection = new QuicConnection(1L, QuicVersion.QUIC_VERSION_1, new InetSocketAddress(0), selectorMock, mockMetadata, new byte[8]);
        
        // Set state to ESTABLISHED
        Field stateField = QuicConnection.class.getDeclaredField("state");
        stateField.setAccessible(true);
        connection.setState(QuicConnection.State.ESTABLISHED);

        NativeCrypto stekMock = mock(NativeCrypto.class);
        sessionTicketServiceMock.when(() -> SessionTicketService.getStekCrypto(any())).thenReturn(stekMock);
    }

    @AfterEach
    void tearDown() {
        cryptoMock.close();
        propertiesMock.close();
        sessionTicketServiceMock.close();
    }

    @Test
    void testSendNewSessionTicketSlicingSmall() throws Exception {
        runSlicingTest(100, 100); // Small payload, 100 bytes of data -> multiple chunks
    }

    @Test
    void testSendNewSessionTicketNoSlicing() throws Exception {
        runSlicingTest(1500, 100); // Large payload, 100 bytes of data -> 1 chunk
    }

    @Test
    void testSendNewSessionTicketSlicingExactTwo() throws Exception {
        // Overhead is 58. For 100 payload, maxChunk is 42.
        // If we want exactly 2 chunks, data should be between 43 and 84.
        runSlicingTest(100, 60); 
    }

    private void runSlicingTest(int maxUdpPayloadSize, int dataSize) throws Exception {
        int maxChunkSize = maxUdpPayloadSize - 17 - 16 - 25;
        if (maxChunkSize <= 0) maxChunkSize = 1; // Safeguard

        mockMetadata.clientMetadata = new ConnectionMetadata.ClientMetadataNegotiated(
                "h3", 30000, new ArrayList<>(), new HashMap<>(), maxUdpPayloadSize,
                1000000, 65536, 65536, 65536, 100, 100,
                new ArrayList<>(), 3, new ArrayList<>(), CipherMode.TLS_AES_128_GCM_SHA256_ID, new byte[32],
                -1, null);

        cryptoMock.when(() -> SessionTicketService.createNewSessionTicket(any(), any(), anyLong(), any(), any()))
                .thenAnswer(inv -> {
                    java.io.DataOutputStream dos = inv.getArgument(4);
                    dos.write(new byte[dataSize]);
                    return null;
                });

        mockMetadata.serverApplicationCrypto = mock(NativeCrypto.class);
        
        org.jquic.quic.paths.ConnectionPathController pathControllerMock = mock(org.jquic.quic.paths.ConnectionPathController.class);
        Field pathControllerField = QuicConnection.class.getDeclaredField("connectionPathController");
        pathControllerField.setAccessible(true);
        pathControllerField.set(connection, pathControllerMock);

        connection.sendNewSessionTicket(null);

        ArgumentCaptor<PoolBuffer> captor = ArgumentCaptor.forClass(PoolBuffer.class);
        verify(pathControllerMock, atLeast(1)).sendFrame(captor.capture(), eq(org.jquic.quic.packets.PacketPhase.APPLICATION));
        
        List<PoolBuffer> chunks = captor.getAllValues();
        int expectedChunks = (int) Math.ceil((double) dataSize / maxChunkSize);
        assertEquals(expectedChunks, chunks.size(), "Number of chunks mismatch for dataSize=" + dataSize + " and maxChunkSize=" + maxChunkSize);
        
        for (PoolBuffer chunk : chunks) {
            ByteBuffer buf = chunk.buf();
            assertEquals(0x06, buf.get(buf.position()), "CRYPTO frame header missing");
            // Check that it doesn't exceed the limit
            // Each chunk is wrapped in CRYPTO header (max 17) and later encrypted (+16 tag) and short header (+25)
            // But sendNewSessionTicket calculates maxChunkSize such that chunk + overhead fits in maxUdpPayloadSize
            assertTrue(buf.remaining() <= maxChunkSize + 17, "Chunk too large: " + buf.remaining() + " > " + (maxChunkSize + 17));
        }
    }
}
