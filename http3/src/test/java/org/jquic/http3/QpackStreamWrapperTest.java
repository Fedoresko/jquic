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

import org.jquic.http3.qpack.QpackInstruction;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

public class QpackStreamWrapperTest {

    static class MockStreamContext extends Http3StreamContext {
        private final Http3ClientStreamRole role;
        private final List<byte[]> dataToRead = new ArrayList<>();

        MockStreamContext(Http3ClientStreamRole role) {
            super(role);
            this.role = role;
        }

        @Override
        public Http3ClientStreamRole getRole() {
            return role;
        }

        void addData(byte[] data) {
            dataToRead.add(data);
        }

        @Override
        public byte @NonNull [] readAllBytes() {
            if (dataToRead.isEmpty()) return new byte[0];
            return dataToRead.removeFirst();
        }
    }

    @Test
    public void testDecoderStreamPartialReads() throws IOException {
        MockStreamContext context = new MockStreamContext(Http3ClientStreamRole.QPACK_DECODER);
        QpackStreamWrapper wrapper = new QpackStreamWrapper(context);

        // Section Acknowledgment (Section 4.4.2) - 1xxx xxxx
        // Stream ID 100 -> 1 1100100 -> 0x80 | 0x64 = 0xE4
        byte[] fullInstruction = new byte[]{(byte) 0xE4};
        
        context.addData(new byte[]{fullInstruction[0]});
        QpackInstruction instruction = wrapper.getNextInstruction();
        assertInstanceOf(QpackInstruction.DecoderInstruction.SectionAck.class, instruction);
        assertEquals(100, ((QpackInstruction.DecoderInstruction.SectionAck) instruction).streamId());
        assertNull(wrapper.getNextInstruction());

        // Stream ID 1000 -> 1 111111 (0x7F) then 1000 - 127 = 873
        // 873 = 0x369. 0x69 | 0x80 = 0xE9. 0x06.
        // Full: 0xFF, 0xE9, 0x06
        byte[] largeInstruction = new byte[]{(byte) 0xFF, (byte) 0xE9, (byte) 0x06};
        
        context.addData(new byte[]{largeInstruction[0]});
        assertNull(wrapper.getNextInstruction());
        
        context.addData(new byte[]{largeInstruction[1]});
        assertNull(wrapper.getNextInstruction());
        
        context.addData(new byte[]{largeInstruction[2]});
        instruction = wrapper.getNextInstruction();
        assertInstanceOf(QpackInstruction.DecoderInstruction.SectionAck.class, instruction);
        assertEquals(1000, ((QpackInstruction.DecoderInstruction.SectionAck) instruction).streamId());
    }

    @Test
    public void testEncoderStreamPartialReads() throws IOException {
        MockStreamContext context = new MockStreamContext(Http3ClientStreamRole.QPACK_ENCODER);
        QpackStreamWrapper wrapper = new QpackStreamWrapper(context);

        // Insert With Name Reference (Section 4.3.2) - 1xxx xxxx
        // Static, index 1, value "v" (length 1)
        // 1 1 000001 -> 0xC1
        // 0 0000001 -> 0x01
        // 'v' -> 0x76
        byte[] instructionBytes = new byte[]{(byte) 0xC1, 0x01, 0x76};

        context.addData(new byte[]{instructionBytes[0], instructionBytes[1]});
        assertNull(wrapper.getNextInstruction());

        context.addData(new byte[]{instructionBytes[2]});
        QpackInstruction instruction = wrapper.getNextInstruction();
        assertInstanceOf(QpackInstruction.EncoderInstruction.InsertWithNameRef.class, instruction);
        QpackInstruction.EncoderInstruction.InsertWithNameRef i = (QpackInstruction.EncoderInstruction.InsertWithNameRef) instruction;
        assertTrue(i.isStatic());
        assertEquals(1, i.nameIndex());
        assertEquals("v", i.value());
    }

    @Test
    public void testMultipleInstructionsInOneRead() throws IOException {
        MockStreamContext context = new MockStreamContext(Http3ClientStreamRole.QPACK_DECODER);
        QpackStreamWrapper wrapper = new QpackStreamWrapper(context);

        byte[] inst1 = new byte[]{(byte) 0x81}; // Section Ack, Stream 1
        byte[] inst2 = new byte[]{(byte) 0x42}; // Stream Cancel, Stream 2
        
        byte[] both = new byte[]{inst1[0], inst2[0]};
        context.addData(both);

        QpackInstruction instruction1 = wrapper.getNextInstruction();
        assertInstanceOf(QpackInstruction.DecoderInstruction.SectionAck.class, instruction1);
        assertEquals(1, ((QpackInstruction.DecoderInstruction.SectionAck) instruction1).streamId());

        QpackInstruction instruction2 = wrapper.getNextInstruction();
        assertInstanceOf(QpackInstruction.DecoderInstruction.StreamCancel.class, instruction2);
        assertEquals(2, ((QpackInstruction.DecoderInstruction.StreamCancel) instruction2).streamId());
        
        assertNull(wrapper.getNextInstruction());
    }
}
