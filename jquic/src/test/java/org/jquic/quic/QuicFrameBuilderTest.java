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

import org.junit.jupiter.api.Test;
import java.nio.ByteBuffer;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class QuicFrameBuilderTest {

    @Test
    void testWriteNewConnectionIdFrame() {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        buffer.position(10); // Start at non-zero to verify position reset
        long sequenceNumber = 123456789L;
        long retirePriorTo = 100000000L;
        byte[] connectionId = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] resetToken = new byte[16];
        Arrays.fill(resetToken, (byte) 0xAA);

        QuicFrameBuilder.writeNewConnectionIdFrame(buffer, sequenceNumber, retirePriorTo, connectionId, resetToken);
        
        assertEquals(10, buffer.position());
        assertTrue(buffer.limit() > 10);
        
        // Use a duplicate to read without affecting the original buffer's position
        ByteBuffer readBuf = buffer.duplicate();

        assertEquals(QuicFrameBuilder.NEW_CONNECTION_ID, readBuf.get());
        assertEquals(sequenceNumber, QuicVarint.read(readBuf));
        assertEquals(retirePriorTo, QuicVarint.read(readBuf));
        assertEquals(connectionId.length, readBuf.get() & 0xFF);
        byte[] readCid = new byte[connectionId.length];
        readBuf.get(readCid);
        assertArrayEquals(connectionId, readCid);
        byte[] readToken = new byte[16];
        readBuf.get(readToken);
        assertArrayEquals(resetToken, readToken);
        assertFalse(readBuf.hasRemaining());
    }

    @Test
    void testWriteRetireConnectionIdFrame() {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        buffer.position(5);
        long sequenceNumber = 987654321L;

        QuicFrameBuilder.writeRetireConnectionIdFrame(buffer, sequenceNumber);
        
        assertEquals(5, buffer.position());
        assertTrue(buffer.limit() > 5);

        ByteBuffer readBuf = buffer.duplicate();

        assertEquals(QuicFrameBuilder.RETIRE_CONNECTION_ID, readBuf.get());
        assertEquals(sequenceNumber, QuicVarint.read(readBuf));
        assertFalse(readBuf.hasRemaining());
    }

    @Test
    void testWriteNewConnectionIdFrameInvalidArgs() {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        byte[] validCid = new byte[8];
        byte[] validToken = new byte[16];

        // CID too long
        assertThrows(IllegalArgumentException.class, () -> 
            QuicFrameBuilder.writeNewConnectionIdFrame(buffer, 1, 0, new byte[21], validToken));

        // Token wrong length
        assertThrows(IllegalArgumentException.class, () -> 
            QuicFrameBuilder.writeNewConnectionIdFrame(buffer, 1, 0, validCid, new byte[15]));

        // retire_prior_to > sequence_number
        assertThrows(IllegalArgumentException.class, () -> 
            QuicFrameBuilder.writeNewConnectionIdFrame(buffer, 1, 2, validCid, validToken));
    }
}
