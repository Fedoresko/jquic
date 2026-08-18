package org.jquic.quic;

import org.junit.jupiter.api.Test;
import java.nio.ByteBuffer;
import static org.junit.jupiter.api.Assertions.*;

public class QuicPathChallengeFrameTest {

    @Test
    public void testWritePathChallengeFrame() {
        ByteBuffer buffer = ByteBuffer.allocate(10);
        byte[] data = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        
        QuicFrameBuilder.writePathChallengeFrame(buffer, data);
        
        assertEquals((byte) 0x1a, buffer.get(), "Frame type should be 0x1a");
        byte[] readData = new byte[8];
        buffer.get(readData);
        assertArrayEquals(data, readData, "Data should match");
        assertFalse(buffer.hasRemaining(), "No more data should be in buffer");
    }

    @Test
    public void testWritePathResponseFrame() {
        ByteBuffer buffer = ByteBuffer.allocate(10);
        byte[] data = new byte[]{8, 7, 6, 5, 4, 3, 2, 1};

        QuicFrameBuilder.writePathResponseFrame(buffer, data);

        assertEquals((byte) 0x1b, buffer.get(), "Frame type should be 0x1b");
        byte[] readData = new byte[8];
        buffer.get(readData);
        assertArrayEquals(data, readData, "Data should match");
        assertFalse(buffer.hasRemaining(), "No more data should be in buffer");
    }

    @Test
    public void testWritePathChallengeFrameInvalidLength() {
        ByteBuffer buffer = ByteBuffer.allocate(10);
        byte[] data = new byte[]{1, 2, 3, 4, 5, 6, 7}; // Too short
        
        assertThrows(IllegalArgumentException.class, () -> {
            QuicFrameBuilder.writePathChallengeFrame(buffer, data);
        });
    }
}
