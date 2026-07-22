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

        ByteBuffer encoded = StreamFrameProcessor.encodeDatagramFrame(buffer, true);

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

        ByteBuffer encoded = StreamFrameProcessor.encodeDatagramFrame(buffer, false);

        assertEquals(0x30, encoded.get());
        byte[] actualData = new byte[encoded.remaining()];
        encoded.get(actualData);
        for (int i = 0; i < data.length; i++) {
            assertEquals(data[i], actualData[i]);
        }
    }
}
