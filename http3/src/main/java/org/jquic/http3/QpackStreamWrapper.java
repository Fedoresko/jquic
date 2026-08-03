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
package org.jquic.http3;

import org.jquic.http3.qpack.Huffman;
import org.jquic.http3.qpack.QpackInstruction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Deque;

public class QpackStreamWrapper implements StreamWrapper {
    private static final Logger logger = LoggerFactory.getLogger(QpackStreamWrapper.class);

    private final Http3StreamContext context;
    private final Deque<QpackInstruction> instructions = new ArrayDeque<>();
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public QpackStreamWrapper(Http3StreamContext context) {
        this.context = context;
    }

    private void processMoreData() throws IOException {
        byte[] data = context.readAllBytes();
        if (data.length > 0) {
            buffer.write(data);
        }

        while (buffer.size() > 0) {
            byte[] bufferedBytes = buffer.toByteArray();
            ByteBuffer bb = ByteBuffer.wrap(bufferedBytes);
            int posBefore = bb.position();
            try {
                QpackInstruction instruction = parseInstruction(bb);
                if (instruction != null) {
                    instructions.add(instruction);

                    // Remove processed bytes from buffer
                    int remainingCount = bb.remaining();
                    byte[] remaining = new byte[remainingCount];
                    bb.get(remaining);
                    buffer.reset();
                    if (remainingCount > 0) {
                        buffer.write(remaining);
                    }
                    if (bb.position() == posBefore) {
                        // Safety break to avoid infinite loop if parseInstruction doesn't consume anything but returns non-null
                        break; 
                    }
                } else {
                    // Incomplete instruction
                    break;
                }
            } catch (BufferUnderflowException e) {
                // Incomplete instruction
                break;
            }
        }
    }

    private QpackInstruction parseInstruction(ByteBuffer bb) {
        if (!bb.hasRemaining()) return null;
        int initialPos = bb.position();
        int firstByte = bb.get() & 0xFF;

        if (context.getRole() == Http3ClientStreamRole.QPACK_ENCODER) {
            // Encoder Instructions (Section 4.3)
            if ((firstByte & 0x80) != 0) {
                // Insert With Name Reference (Section 4.3.2) - 1xxx xxxx
                bb.position(initialPos);
                Long index = readPrefixInt(bb, 6);
                if (index == null) return null;
                String value = readString(bb);
                if (value == null) return null;
                boolean isStatic = (firstByte & 0x40) != 0;
                return new QpackInstruction.EncoderInstruction.InsertWithNameRef(isStatic, index.intValue(), value);
            } else if ((firstByte & 0x40) != 0) {
                // Insert With Literal Name (Section 4.3.3) - 01xx xxxx
                bb.position(initialPos);
                String name = readString(bb, 5);
                if (name == null) return null;
                String value = readString(bb);
                if (value == null) return null;
                return new QpackInstruction.EncoderInstruction.InsertWithLiteralName(name, value);
            } else if ((firstByte & 0x20) != 0) {
                // Set Dynamic Table Capacity (Section 4.3.1) - 001x xxxx
                bb.position(initialPos);
                Long capacity = readPrefixInt(bb, 5);
                if (capacity == null) return null;
                return new QpackInstruction.EncoderInstruction.SetCapacity(capacity);
            } else {
                // Duplicate (Section 4.3.4) - 000x xxxx
                bb.position(initialPos);
                Long index = readPrefixInt(bb, 5);
                if (index == null) return null;
                return new QpackInstruction.EncoderInstruction.Duplicate(index.intValue());
            }
        } else if (context.getRole() == Http3ClientStreamRole.QPACK_DECODER) {
            // Decoder Instructions (Section 4.4)
            if ((firstByte & 0x80) != 0) {
                // Section Acknowledgment (Section 4.4.2) - 1xxx xxxx
                bb.position(initialPos);
                Long streamId = readPrefixInt(bb, 7);
                if (streamId == null) return null;
                return new QpackInstruction.DecoderInstruction.SectionAck(streamId);
            } else if ((firstByte & 0x40) != 0) {
                // Stream Cancellation (Section 4.4.1) - 01xx xxxx
                bb.position(initialPos);
                Long streamId = readPrefixInt(bb, 6);
                if (streamId == null) return null;
                return new QpackInstruction.DecoderInstruction.StreamCancel(streamId);
            } else {
                // Insert Count Increment (Section 4.4.3) - 00xx xxxx
                bb.position(initialPos);
                Long increment = readPrefixInt(bb, 6);
                if (increment == null) return null;
                return new QpackInstruction.DecoderInstruction.InsertCountIncrement(increment);
            }
        }
        return null;
    }

    private Long readPrefixInt(ByteBuffer bb, int prefixBits) {
        if (!bb.hasRemaining()) return null;
        int initialPos = bb.position();
        int firstByte = bb.get() & 0xFF;
        int mask = (1 << prefixBits) - 1;
        long value = firstByte & mask;
        if (value < mask) return value;

        int shift = 0;
        while (bb.hasRemaining()) {
            int b = bb.get() & 0xFF;
            value += (long) (b & 0x7F) << shift;
            if ((b & 0x80) == 0) return value;
            shift += 7;
            if (shift >= 64) break; // Error
        }
        bb.position(initialPos); // Rewind
        return null;
    }

    private String readString(ByteBuffer bb) {
        if (!bb.hasRemaining()) return null;
        int firstByte = bb.get() & 0xFF;
        int initialPos = bb.position();
        bb.position(initialPos - 1);
        return readString(bb, 7);
    }

    private String readString(ByteBuffer bb, int prefixBits) {
        int initialPos = bb.position();
        Long length = readPrefixInt(bb, prefixBits);
        if (length == null) return null;

        if (bb.remaining() < length) {
            bb.position(initialPos); // Restore position for next try
            return null;
        }

        byte[] data = new byte[length.intValue()];
        bb.get(data);

        int firstByte = bb.get(initialPos) & 0xFF;
        boolean huffman = (firstByte & (1 << prefixBits)) != 0;

        if (huffman) {
            return new String(Huffman.decode(ByteBuffer.wrap(data)));
        } else {
            return new String(data);
        }
    }

    public QpackInstruction getNextInstruction() throws IOException {
        processMoreData();
        QpackInstruction instruction = instructions.poll();
        if (instruction != null) {
            logger.debug("Returning instruction: {}", instruction);
        }
        return instruction;
    }
}
