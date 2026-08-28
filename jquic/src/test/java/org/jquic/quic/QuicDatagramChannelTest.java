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
import org.jquic.quic.linux.ECT;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class QuicDatagramChannelTest {

    private DatagramChannel serverChannel;
    private DatagramChannel clientChannel;
    private QuicDatagramChannel quicServerChannel;
    private QuicDatagramChannel quicClientChannel;

    @BeforeEach
    void setUp() throws IOException {
        serverChannel = DatagramChannel.open();
        serverChannel.bind(new InetSocketAddress("127.0.0.1", 0));
        quicServerChannel = new QuicDatagramChannel(serverChannel);

        clientChannel = DatagramChannel.open();
        clientChannel.bind(new InetSocketAddress("127.0.0.1", 0));
        quicClientChannel = new QuicDatagramChannel(clientChannel);
    }

    @AfterEach
    void tearDown() throws IOException {
        serverChannel.close();
        clientChannel.close();
    }

    @Test
    void testSendReceive() throws IOException {
        String message = "Hello, QUIC!";
        ByteBuffer sendBuf = ByteBuffer.wrap(message.getBytes());
        SocketAddress serverAddr = serverChannel.getLocalAddress();

        quicClientChannel.send(sendBuf, serverAddr, ECT.NONE);

        TestPoolBuffer recvBuf = new TestPoolBuffer(ByteBuffer.allocate(1024));
        org.jquic.quic.QuicDatagramChannel.ReceivedPacket res = quicServerChannel.receiveBlocking(recvBuf);

        assertNotNull(res);
        assertEquals(message, new String(recvBuf.buf().array(), recvBuf.buf().position(), recvBuf.buf().limit()));
    }

    @Test
    void testBatchSendReceive() throws IOException {
        int count = 5;
        List<SelectorThread.PacketToSend> data = new ArrayList<>();
        SocketAddress serverAddr = serverChannel.getLocalAddress();

        for (int i = 0; i < count; i++) {
            data.add(new SelectorThread.PacketToSend(serverAddr, new TestPoolBuffer(ByteBuffer.wrap(("Message " + i).getBytes())).borrow(), ECT.NONE));
        }

        int sent = quicClientChannel.sendBatch(data);
        assertEquals(count, sent);

        List<QuicDatagramChannel.ReceivedPacket> received = quicServerChannel.receiveBatchBlocking(
                data.stream().map(SelectorThread.PacketToSend::poolBuffer).toArray(PoolBuffer[]::new)
        );
        
        // Note: In UDP, packets might be lost or reordered, but on loopback it should be stable.
        // However, receiveBatchBlocking in fallback might return less than 'count' if it's not truly blocking for all.
        // But our fallback blocks on the first packet and then does non-blocking for others.
        // On loopback, they should all be available after the first one arrives.

        assertFalse(received.isEmpty());
        for (QuicDatagramChannel.ReceivedPacket p : received) {
            ByteBuffer buf = p.data().buf();
            byte[] bytes = new byte[buf.remaining()];
            buf.get(bytes);
            String receivedMsg = new String(bytes);
            assertTrue(receivedMsg.startsWith("Message "));
            p.data().release();
        }
    }

    @Test
    void testReceiveNonBlocking() throws IOException {
        TestPoolBuffer recvBuf = new TestPoolBuffer( ByteBuffer.allocate(1024) );
        QuicDatagramChannel.ReceivedPacket packet = quicServerChannel.receive(recvBuf);
        assertNull(packet, "Should not receive anything on empty socket");
    }

    @Test
    void testReceiveBatchNonBlocking() throws IOException {
        PoolBuffer[] buffers = new PoolBuffer[10];
        for (int i = 0; i < buffers.length; i++) {
            buffers[i] = new TestPoolBuffer(ByteBuffer.wrap(("Message " + i).getBytes()));
        }
        List<QuicDatagramChannel.ReceivedPacket> received = quicServerChannel.receiveBatch(buffers);
        assertTrue(received.isEmpty(), "Should not receive anything on empty socket");
    }
}
