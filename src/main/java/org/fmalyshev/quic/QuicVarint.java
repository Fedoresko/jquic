package org.fmalyshev.quic;

import java.nio.ByteBuffer;

/**
 * Utility class for QUIC variable-length integer encoding and decoding.
 * RFC 9000 Section 16: Variable-Length Integer Encoding
 */
public class QuicVarint {

    /**
     * Reads a QUIC variable-length integer from a ByteBuffer.
     * 
     * @param buffer The buffer to read from
     * @return The decoded integer value, or 0 if buffer is empty
     */
    public static long read(ByteBuffer buffer) {
        if (!buffer.hasRemaining()) return 0;

        byte first = buffer.get();
        int prefix = (first & 0xC0) >> 6;

        switch (prefix) {
            case 0: return first & 0x3F;
            case 1: return ((first & 0x3F) << 8) | (buffer.get() & 0xFF);
            case 2: return ((first & 0x3F) << 24) | ((buffer.get() & 0xFF) << 16) |
                          ((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF);
            case 3:
                long value = (first & 0x3F);
                for (int i = 0; i < 7; i++) {
                    value = (value << 8) | (buffer.get() & 0xFF);
                }
                return value;
            default: return 0;
        }
    }

    public static int sizeOf(long value) {
        if (value < 64) {
            return 1;
        } else if (value < 16384) {
            return 2;
        } else if (value < 1073741824) {
            return 4;
        }
        return 8;
    }

    /**
     * Writes a QUIC variable-length integer to a ByteBuffer.
     * Uses the shortest encoding possible.
     * 
     * @param buffer The buffer to write to
     * @param value The value to encode (must be non-negative)
     * @throws IllegalArgumentException if value is negative
     */
    public static void write(ByteBuffer buffer, long value) {
        if (value < 0) {
            throw new IllegalArgumentException("Varint cannot be negative: " + value);
        }
        if (value < 64) {
            buffer.put((byte) value);
        } else if (value < 16384) {
            buffer.put((byte) (0x40 | (value >> 8)));
            buffer.put((byte) value);
        } else if (value < 1073741824) {
            buffer.put((byte) (0x80 | (value >> 24)));
            buffer.put((byte) (value >> 16));
            buffer.put((byte) (value >> 8));
            buffer.put((byte) value);
        } else {
            buffer.put((byte) (0xC0 | (value >> 56)));
            for (int i = 6; i >= 0; i--) {
                buffer.put((byte) (value >> (i * 8)));
            }
        }
    }
}
