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
import org.jquic.quic.packets.PacketNumberSpace;
import org.jquic.quic.streamapi.ConnectionStreamManager;
import org.jquic.quic.streamapi.frames.StreamResetFrameAck;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.ByteBuffer;

import static org.jquic.quic.QuicFrameBuilder.*;
import static org.jquic.quic.streamapi.impl.StreamFrameWriter.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class AckedPacketsHandlerTest {

    private QuicConnection connection;
    private ConnectionStreamManager streamManager;
    private AckedPacketsHandler handler;
    private PacketNumberSpace.SentPacket sentPacket;
    private PoolBuffer poolBuffer;

    @BeforeEach
    void setUp() {
        connection = mock(QuicConnection.class);
        streamManager = mock(ConnectionStreamManager.class);
        when(connection.getConnectionStreamManager()).thenReturn(streamManager);
        handler = new AckedPacketsHandler(connection);
        sentPacket = mock(PacketNumberSpace.SentPacket.class);
        poolBuffer = mock(PoolBuffer.class);
        when(sentPacket.getUnencryptedPayload()).thenReturn(poolBuffer);
    }

    @Test
    void testStreamFrameAcknowledgment() {
        // STREAM frame: type=0x08 | OFF=0x04 | LEN=0x02 | FIN=0x01
        // Let's use 0x0E (OFF | LEN)
        byte frameType = (byte) (FRAME_TYPE_STREAM | 0x04 | 0x02);
        long streamId = 123;
        long offset = 456;
        long length = 789;

        ByteBuffer buffer = ByteBuffer.allocate(20);
        buffer.put(frameType);
        QuicVarint.write(buffer, streamId);
        QuicVarint.write(buffer, offset);
        QuicVarint.write(buffer, length);
        buffer.flip();

        when(poolBuffer.buf()).thenReturn(buffer);

        handler.onPacketAcknowledged(1L, sentPacket);

        verify(streamManager).onStreamAck(streamId, offset, length);
    }

    @Test
    void testResetStreamFrameAcknowledgment() {
        long streamId = 456;
        ByteBuffer buffer = ByteBuffer.allocate(10);
        buffer.put(FRAME_TYPE_RESET_STREAM);
        QuicVarint.write(buffer, streamId);
        buffer.flip();

        when(poolBuffer.buf()).thenReturn(buffer);

        handler.onPacketAcknowledged(1L, sentPacket);

        ArgumentCaptor<StreamResetFrameAck> captor = ArgumentCaptor.forClass(StreamResetFrameAck.class);
        verify(streamManager).onProtocolFrame(captor.capture());
        assertEquals(streamId, captor.getValue().streamId);
    }

    @Test
    void testNewConnectionIdAcknowledgment() {
        long seqNum = 7;
        ByteBuffer buffer = ByteBuffer.allocate(30);
        buffer.put(NEW_CONNECTION_ID);
        QuicVarint.write(buffer, seqNum);
        QuicVarint.write(buffer, 0); // retirePriorTo
        buffer.put((byte) 8); // cid len
        buffer.put(new byte[8]); // cid
        buffer.put(new byte[16]); // stateless reset token
        buffer.flip();

        when(poolBuffer.buf()).thenReturn(buffer);

        handler.onPacketAcknowledged(1L, sentPacket);
    }

    @Test
    void testRetireConnectionIdAcknowledgment() {
        long seqNum = 42;
        ByteBuffer buffer = ByteBuffer.allocate(10);
        buffer.put(RETIRE_CONNECTION_ID);
        QuicVarint.write(buffer, seqNum);
        buffer.flip();

        when(poolBuffer.buf()).thenReturn(buffer);

        handler.onPacketAcknowledged(1L, sentPacket);

    }

    @Test
    void testSkippableFrames() {
        // Test PING, PADDING, CRYPTO, etc. (some are handled by skipping)
        // AckedPacketsHandler should just skip them without calling anything on streamManager or connection
        
        // PING is actually not in AckedPacketsHandler.onPacketAcknowledged if it doesn't have a specific handling
        // AckedPacketsHandler only handles a subset of frames.
        
        // Let's test CRYPTO
        ByteBuffer buffer = ByteBuffer.allocate(20);
        buffer.put(CRYPTO);
        QuicVarint.write(buffer, 0); // offset
        QuicVarint.write(buffer, 10); // length
        buffer.put(new byte[10]);
        buffer.flip();

        when(poolBuffer.buf()).thenReturn(buffer);
        handler.onPacketAcknowledged(1L, sentPacket);

        verifyNoInteractions(streamManager);
        // connection.getConnectionStreamManager() IS called, but that's fine.
    }

    @Test
    void testMultipleFramesInPacket() {
        // STREAM + PING + NEW_CONNECTION_ID
        byte streamFrameType = (byte) (FRAME_TYPE_STREAM | 0x02); // LEN bit
        long streamId = 123;
        long length = 10;
        
        long seqNum = 9;

        ByteBuffer buffer = ByteBuffer.allocate(64);
        // Frame 1: STREAM
        buffer.put(streamFrameType);
        QuicVarint.write(buffer, streamId);
        QuicVarint.write(buffer, length);
        buffer.put(new byte[(int) length]);

        // Frame 2: PING
        buffer.put(PING);

        // Frame 3: NEW_CONNECTION_ID
        buffer.put(NEW_CONNECTION_ID);
        QuicVarint.write(buffer, seqNum);
        QuicVarint.write(buffer, 0); // retirePriorTo
        buffer.put((byte) 8); // cid len
        buffer.put(new byte[8]); // cid
        buffer.put(new byte[16]); // stateless reset token
        
        buffer.flip();

        when(poolBuffer.buf()).thenReturn(buffer);

        handler.onPacketAcknowledged(1L, sentPacket);

        verify(streamManager).onStreamAck(streamId, 0, length);
        verify(streamManager, times(1)).onStreamAck(anyLong(), anyLong(), anyLong());
    }
    @Test
    void testMultipleFramesWithPaddingAndCrypto() {
        // PADDING + CRYPTO + PADDING + STREAM + PADDING
        byte streamFrameType = (byte) (FRAME_TYPE_STREAM | 0x02); // LEN bit
        long streamId = 456;
        long length = 5;

        ByteBuffer buffer = ByteBuffer.allocate(64);
        buffer.put((byte) 0x00); // PADDING
        
        // CRYPTO
        buffer.put(CRYPTO);
        QuicVarint.write(buffer, 0); // offset
        QuicVarint.write(buffer, 10); // length
        buffer.put(new byte[10]);
        
        buffer.put((byte) 0x00); // PADDING
        
        // STREAM
        buffer.put(streamFrameType);
        QuicVarint.write(buffer, streamId);
        QuicVarint.write(buffer, length);
        buffer.put(new byte[(int) length]);
        
        buffer.put((byte) 0x00); // PADDING
        buffer.flip();

        when(poolBuffer.buf()).thenReturn(buffer);

        handler.onPacketAcknowledged(1L, sentPacket);

        verify(streamManager).onStreamAck(streamId, 0, length);
        verify(connection, atLeastOnce()).getConnectionStreamManager();
        verifyNoMoreInteractions(connection);
    }
}
