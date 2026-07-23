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

import java.io.DataOutputStream;
import java.io.IOException;
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

    public static void write(DataOutputStream out, long value) throws IOException {
        if (value < 0) {
            throw new IllegalArgumentException("Varint cannot be negative: " + value);
        }
        if (value < 64) {
            out.write((byte) value);
        } else if (value < 16384) {
            out.write((byte) (0x40 | (value >> 8)));
            out.write((byte) value);
        } else if (value < 1073741824) {
            out.write((byte) (0x80 | (value >> 24)));
            out.write((byte) (value >> 16));
            out.write((byte) (value >> 8));
            out.write((byte) value);
        } else {
            out.write((byte) (0xC0 | (value >> 56)));
            for (int i = 6; i >= 0; i--) {
                out.write((byte) (value >> (i * 8)));
            }
        }
    }
}

