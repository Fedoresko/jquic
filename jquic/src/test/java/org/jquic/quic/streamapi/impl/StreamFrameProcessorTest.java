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
package org.jquic.quic.streamapi.impl;

import org.jquic.quic.QuicVarint;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class StreamFrameProcessorTest {

    @Test
    public void testEncodeDatagramFrameWithLength() {
        byte[] data = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
        int headerMaxLen = 5; // 1 (type) + 4 (max varint length for small size)
        ByteBuffer buffer = ByteBuffer.allocateDirect(headerMaxLen + data.length);
        buffer.position(headerMaxLen);
        buffer.put(data);
        buffer.flip();
        buffer.position(headerMaxLen);

        ByteBuffer encoded = StreamFrameWriter.encodeDatagramFrame(buffer, true);

        assertEquals(0x31, encoded.get());
        long length = QuicVarint.read(encoded);
        assertEquals(data.length, length);
        byte[] actualData = new byte[encoded.remaining()];
        encoded.get(actualData);
        for (int i = 0; i < data.length; i++) {
            assertEquals(data[i], actualData[i]);
        }
    }

    @Test
    public void testEncodeDatagramFrameWithoutLength() {
        byte[] data = new byte[]{0x06, 0x07, 0x08};
        int headerMaxLen = 1; // 1 (type)
        ByteBuffer buffer = ByteBuffer.allocateDirect(headerMaxLen + data.length);
        buffer.position(headerMaxLen);
        buffer.put(data);
        buffer.flip();
        buffer.position(headerMaxLen);

        ByteBuffer encoded = StreamFrameWriter.encodeDatagramFrame(buffer, false);

        assertEquals(0x30, encoded.get());
        byte[] actualData = new byte[encoded.remaining()];
        encoded.get(actualData);
        for (int i = 0; i < data.length; i++) {
            assertEquals(data[i], actualData[i]);
        }
    }
}

