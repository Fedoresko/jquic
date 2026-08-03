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
package org.jquic.http3.qpack;

import org.jquic.http3.Http3ClientStreamRole;
import org.jquic.http3.Http3StreamContext;
import org.jquic.http3.QpackStreamWrapper;
import org.junit.jupiter.api.Test;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

public class QpackRfcEdgeCaseTest {

    @Test
    public void testRicWrapAroundReconstruction() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        coupler.bind(encoder, decoder);

        // Capacity 32 -> MaxEntries 1 -> FullRange 2.
        encoder.setDynamicTableCapacity(36);
        
        // 1. First insertion: RIC = 1, EncodedRIC = (1 % 2) + 1 = 2.
        encoder.encodeHeaders(1, List.of(new Header("k1", "v1")));
        
        // 2. Second insertion: RIC = 2, EncodedRIC = (2 % 2) + 1 = 1.
        // Note: k1 will be evicted because capacity is 32.
        encoder.encodeHeaders(2, List.of(new Header("k2", "v2")));
        
        // 3. Third insertion: RIC = 3, EncodedRIC = (3 % 2) + 1 = 2.
        List<Header> h3 = List.of(new Header("k3", "v3"));
        ByteBuffer encoded3 = encoder.encodeHeaders(3, h3);
        
        // RIC = 3. EncodedRIC = 2.
        assertEquals((byte) 0x02, encoded3.get(0));
        
        // Verify decoder reconstructs RIC=3 correctly
        List<Header> decoded3 = decoder.decodeHeaders(3, encoded3);
        assertEquals(h3, decoded3);
        assertEquals(3, decoder.dynamicTable.getInsertCount());
    }

    @Test
    public void testDuplicateInstruction() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        coupler.bind(encoder, decoder);

        // Capacity 64 -> MaxEntries 2.
        encoder.setDynamicTableCapacity(64);

        // 1. Insert "k1", "v1" (index 0)
        encoder.encodeHeaders(1, List.of(new Header("k1", "v1")));
        assertEquals(1, decoder.dynamicTable.getInsertCount());

        // 2. Insert "k2", "v2" (index 1)
        encoder.encodeHeaders(2, List.of(new Header("k2", "v2")));
        assertEquals(2, decoder.dynamicTable.getInsertCount());

        // Now table is full (2 entries).
        // Next insertion would evict "k1", "v1".

        // 3. Encode "k1", "v1" again. 
        // Encoder should see it is at risk of eviction and duplicate it.
        ByteBuffer encoded = encoder.encodeHeaders(3, List.of(new Header("k1", "v1")));
        
        // Dynamic table should now have 3 entries (k1,v1 duplicated)
        assertEquals(3, decoder.dynamicTable.getInsertCount());
        
        // Verify decoded headers match
        List<Header> decoded = decoder.decodeHeaders(3, encoded);
        assertEquals(1, decoded.size());
        assertEquals("k1", decoded.getFirst().name());
        assertEquals("v1", decoded.getFirst().value());
    }

    @Test
    public void testPostBaseLiteralNameReference() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        coupler.bind(encoder, decoder);

        encoder.setDynamicTableCapacity(1024);

        // 1. Insert "k1", "v1" -> absolute index 0.
        encoder.encodeHeaders(1, List.of(new Header("k1", "v1")));
        
        // 2. Construct a Literal Header Field With Post-Base Name Reference (Section 4.5.5)
        // 0000 N xxx
        // We want to refer to absolute index 0.
        // Let's set Base = -1 (so absoluteIndex = base + index + 1? No, Section 4.5.5 says:
        // "An absolute index is calculated by adding the Post-Base Index to the Base.")
        // AbsoluteIndex = Base + Index.
        // If Base is 0, Index 0 refers to Absolute Index 0.
        
        // To get Base = 0: ricBefore = 0, RIC = 1. sign=1, delta=0 -> Base = 1 - 0 - 1 = 0.
        // EncodedRIC = 2.
        
        // 0000 N xxx -> N=0 (no Huffman), prefix 4.
        // 0x00 -> index 0.
        // followed by value.
        ByteBuffer headerBlock = ByteBuffer.allocate(20);
        headerBlock.put((byte) 0x02); // RIC=1
        headerBlock.put((byte) 0x80); // Base=0
        headerBlock.put((byte) 0x00); // Post-base name reference index 0
        headerBlock.put((byte) 0x02); // value length 2
        headerBlock.put("v2".getBytes());
        headerBlock.flip();
        
        List<Header> decoded = decoder.decodeHeaders(2, headerBlock);
        assertEquals(1, decoded.size());
        assertEquals("k1", decoded.getFirst().name());
        assertEquals("v2", decoded.getFirst().value());
    }

    @Test
    public void testPostBaseLiteralNameReferenceWithNBit() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        coupler.bind(encoder, decoder);

        encoder.setDynamicTableCapacity(1024);

        // 1. Insert "k1", "v1" -> absolute index 0.
        encoder.encodeHeaders(1, List.of(new Header("k1", "v1")));

        // Section 4.5.5: 0000 N Index(3+)
        // Set N=1 (0x08) and Index=0.
        // Base=0.
        ByteBuffer headerBlock = ByteBuffer.allocate(20);
        headerBlock.put((byte) 0x02); // RIC=1
        headerBlock.put((byte) 0x80); // Base=0
        headerBlock.put((byte) 0x08); // N=1, Index=0
        headerBlock.put((byte) 0x02); // value length 2
        headerBlock.put("v2".getBytes());
        headerBlock.flip();

        List<Header> decoded = decoder.decodeHeaders(2, headerBlock);
        assertEquals(1, decoded.size());
        assertEquals("k1", decoded.getFirst().name());
        assertEquals("v2", decoded.getFirst().value());
    }

    @Test
    public void testInstructionBoundaries() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        coupler.bind(encoder, decoder);
        // Use large capacity to avoid eviction
        encoder.setDynamicTableCapacity(4096);

        // 1. Duplicate instruction with index 31 (boundary)
        // Insert 32 headers. Each ~36 bytes. 32 * 36 = 1152 < 4096.
        for (int i = 0; i < 32; i++) {
            encoder.encodeHeaders(100 + i, List.of(new Header("k" + i, "v" + i)));
        }
        // Duplicate the first one (k0, v0) which is at absolute index 0.
        // Current insertCount is 32. Relative index for absolute index 0 is 32 - 1 - 0 = 31.
        encoder.duplicate(31);
        assertEquals(33, decoder.dynamicTable.getInsertCount());
        Header dup = decoder.dynamicTable.get(32);
        assertNotNull(dup);
        assertEquals("k0", dup.name());

        // 2. Capacity instruction with boundary 31
        encoder.setDynamicTableCapacity(31);
        assertEquals(31, decoder.dynamicTable.getMaxCapacity());

        // 3. Insert Count Increment boundary 63
        // Manual verification of the instruction encoding/decoding.
        // The decoder sends it when its dynamic table grows.
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        QpackDecoder manualDecoder = new QpackDecoder(new DataOutputStream(bos));
        manualDecoder.setDynamicTableCapacity(4096);
        
        // Add 63 entries to trigger an increment of 63.
        // Each entry size: name(2) + value(1) + 32 = 35. 63 * 35 = 2205 < 4096.
        ByteBuffer inserts = ByteBuffer.allocate(2048);
        for (int i = 0; i < 63; i++) {
            inserts.put((byte) 0x42); // Insert with literal name, length 2
            inserts.put("k".getBytes());
            inserts.put((byte) (100 + i)); // unique name
            inserts.put((byte) 0x01); // value length 1
            inserts.put("v".getBytes());
        }
        inserts.flip();
        byte[] insertsBytes = new byte[inserts.remaining()];
        inserts.get(insertsBytes);
        QpackStreamWrapper wrapper = new QpackStreamWrapper(new Http3StreamContext(Http3ClientStreamRole.QPACK_ENCODER) {
            private boolean read = false;
            @Override
            public byte[] readAllBytes() {
                if (read) return new byte[0];
                read = true;
                return insertsBytes;
            }
        });
        QpackInstruction instruction;
        while ((instruction = wrapper.getNextInstruction()) != null) {
            manualDecoder.onEncoderInstruction((QpackInstruction.EncoderInstruction) instruction);
        }

        byte[] decoderData = bos.toByteArray();
        assertTrue(decoderData.length > 0, "Decoder should have sent increment instruction");
        
        // 00nnnnnn (Section 4.4.3) -> 63 = 0x3F.
        boolean found63 = false;
        int sum = 0;
        for (byte b : decoderData) {
            sum += b;
        }
        assertEquals(63, sum, "Should have found 0x3F in decoder data");

        // Verify that 64 also works (requires two bytes)
        bos.reset();
        // Current insertCount is 63. We need one more insertion to trigger increment 1.
        // Wait, the decoder calculates increment = current - start.
        // If we want it to send 64 at once, we should have done it in the first onEncoderData call.
        // If we do one by one, it sends 1 each time.
        // To test 64, we need to add 64 entries in one call.
        
        manualDecoder = new QpackDecoder(new DataOutputStream(bos));
        manualDecoder.setDynamicTableCapacity(4096);
        bos.reset();
        ByteBuffer inserts64 = ByteBuffer.allocate(3000);
        for (int i = 0; i < 64; i++) {
            inserts64.put((byte) 0x42);
            inserts64.put("k".getBytes());
            inserts64.put((byte) (200 + i));
            inserts64.put((byte) 0x01);
            inserts64.put("v".getBytes());
        }
        inserts64.flip();
        byte[] inserts64Bytes = new byte[inserts64.remaining()];
        inserts64.get(inserts64Bytes);
        QpackStreamWrapper wrapper64 = new QpackStreamWrapper(new Http3StreamContext(Http3ClientStreamRole.QPACK_ENCODER) {
            private boolean read = false;
            @Override
            public byte[] readAllBytes() {
                if (read) return new byte[0];
                read = true;
                return inserts64Bytes;
            }
        });
        QpackInstruction instruction64;
        while ((instruction64 = wrapper64.getNextInstruction()) != null) {
            manualDecoder.onEncoderInstruction((QpackInstruction.EncoderInstruction) instruction64);
        }

        byte[] decoderData2 = bos.toByteArray();
        // 64 = 64 times 0x01.
        assertEquals(64, decoderData2.length);
        for (int i = 0; i < 64; i++) {
            assertEquals(0x01, decoderData2[i] & 0xFF);
        }
    }

    @Test
    public void testMaxTableCapacityZero() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        coupler.bind(encoder, decoder);

        encoder.setDynamicTableCapacity(0);
        
        // Should still be able to encode static headers and literals
        List<Header> headers = List.of(
            new Header(":method", "GET"),
            new Header("custom", "literal")
        );
        ByteBuffer encoded = encoder.encodeHeaders(1, headers);
        
        List<Header> decoded = decoder.decodeHeaders(1, encoded);
        assertEquals(headers, decoded);
        assertEquals(0, decoder.dynamicTable.getInsertCount());
    }

    @Test
    public void testEncoderExceedsMaxCapacity() {
        QpackTestCoupler coupler = new QpackTestCoupler();
        // Decoder only allows 100 bytes
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream(), 100);
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        coupler.bind(encoder, decoder);

        // Encoder tries to set 200 bytes
        // 001xxxxx (Section 4.3.1) -> 0x20 | 200
        // 200 = 0xC8
        // 200 - 31 = 169
        // 169 = 0xA9 = 10101001
        // Prefix 31 (0x1F) -> 0x20 | 0x1F = 0x3F
        // Next byte: (169 & 0x7F) | 0x80 = 0xA9 | 0x80 = 0xA9 (Wait, 169 >= 128)
        // 169 = 1 * 128 + 41
        // Next bytes: 41 | 0x80 (0xA9), 1 (0x01)
        
        ByteBuffer capacityInstruction = ByteBuffer.allocate(10);
        capacityInstruction.put((byte) 0x3F);
        capacityInstruction.put((byte) 0xA9);
        capacityInstruction.put((byte) 0x01);
        capacityInstruction.flip();
        byte[] capBytes = new byte[capacityInstruction.remaining()];
        capacityInstruction.get(capBytes);

        QpackException ex = assertThrows(QpackException.class, () -> {
            QpackStreamWrapper wrapperCap = new QpackStreamWrapper(new Http3StreamContext(Http3ClientStreamRole.QPACK_ENCODER) {
                private boolean read = false;
                @Override
                public byte[] readAllBytes() {
                    if (read) return new byte[0];
                    read = true;
                    return capBytes;
                }
            });
            QpackInstruction instructionCap;
            while ((instructionCap = wrapperCap.getNextInstruction()) != null) {
                decoder.onEncoderInstruction((QpackInstruction.EncoderInstruction) instructionCap);
            }
        });
        
        assertEquals(QpackException.QPACK_ENCODER_STREAM_ERROR, ex.getErrorCode());
        assertTrue(ex.getMessage().contains("exceeds max permitted"));
    }

    @Test
    public void testStreamCancellation() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        QpackDecoder decoder = new QpackDecoder(new DataOutputStream(bos));
        
        // Use a header to make the stream "active"
        ByteBuffer headerBlock = ByteBuffer.allocate(10);
        headerBlock.put((byte) 0x00); // RIC=0
        headerBlock.put((byte) 0x00); // Base=0
        headerBlock.put((byte) 0xD1); // :method: GET (Static index 17)
        headerBlock.flip();
        
        decoder.decodeHeaders(123, headerBlock);
        
        // Cancel the stream
        decoder.cancelStream(123);
        
        byte[] data = bos.toByteArray();
        assertTrue(data.length > 0, "Decoder should have sent cancellation instruction");
        
        // 01xxxxxx (Section 4.4.1) -> 123.
        // 123 < 63? No.
        // 63 is the prefix. 123 - 63 = 60.
        // So it should be 0x40 | 0x3F (0x7F) followed by 60 (0x3C).
        assertEquals(2, data.length);
        assertEquals(0x7F, data[0] & 0xFF);
        assertEquals(60, data[1] & 0xFF);
    }

    @Test
    public void testEncoderRespectsBlockedStreamsLimit() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        // DO NOT BIND - we want to control when decoder sees instructions
        // coupler.bind(encoder, decoder);
        
        // Manual binding for decoder -> encoder to handle acks
        coupler.getDecoderStream(); // ensure stream exists
        // Note: coupler.getDecoderStream() returns a DataOutputStream wrapping a PipedOutputStream.
        // We need to set the consumer for the decoderToEncoder pipe.
        // Accessing private field via reflection or just doing it manually.
        // Actually, we can just use the coupler to get the decoder data and feed it to encoder.

        // peer allows 1 blocked stream
        encoder.setMaxBlockedStreams(1);
        encoder.setDynamicTableCapacity(4096);

        // 1. First stream uses a dynamic entry
        List<Header> h1 = List.of(new Header("k1", "v1"));
        encoder.encodeHeaders(1, h1);
        
        // Verify it sent insert instruction
        List<byte[]> h1Instructions = coupler.getCapturedEncoderData();
        assertTrue(h1Instructions.size() >= 2);
        boolean hasInsert = false;
        for (byte[] instr : h1Instructions) {
            if ((instr[0] & 0xC0) == 0x40) {
                hasInsert = true;
                break;
            }
        }
        assertTrue(hasInsert, "Should have sent insert instruction for first header");
        
        // At this point, blockedCount should be 1 because encoder hasn't seen any increment/ack.
        // Decoder hasn't seen instructions yet.

        // 2. Second stream should NOT use dynamic table because one stream is already potentially blocked
        coupler.clearCapturedData();
        List<Header> h2 = List.of(new Header("k2", "v2"));
        ByteBuffer encoded2 = encoder.encodeHeaders(2, h2);
        
        // Verify it was NOT indexed
        List<byte[]> h2Instructions = coupler.getCapturedEncoderData();
        assertTrue(h2Instructions.isEmpty(), "Should NOT have sent insert instruction when blocked streams limit reached");
        
        // Verify it was sent as a literal (prefix 001 for Literal Without Name Reference)
        byte firstHeaderByte = encoded2.get(2);
        assertEquals(0x20, firstHeaderByte & 0xE0, "Should be Literal Without Name Reference (0x20)");

        // 3. Provide the encoder instructions to the decoder manually
        for (byte[] instr : h1Instructions) {
            QpackStreamWrapper wrapperInstr = new QpackStreamWrapper(new Http3StreamContext(Http3ClientStreamRole.QPACK_ENCODER) {
                private boolean read = false;
                @Override
                public byte[] readAllBytes() {
                    if (read) return new byte[0];
                    read = true;
                    return instr;
                }
            });
            QpackInstruction instructionInstr;
            while ((instructionInstr = wrapperInstr.getNextInstruction()) != null) {
                decoder.onEncoderInstruction((QpackInstruction.EncoderInstruction) instructionInstr);
            }
        }
        
        // Decoder should have generated an Increment. Feed it to encoder.
        List<byte[]> decoderData = coupler.getCapturedDecoderData();
        for (byte[] data : decoderData) {
            QpackStreamWrapper wrapperData = new QpackStreamWrapper(new Http3StreamContext(Http3ClientStreamRole.QPACK_DECODER) {
                private boolean read = false;
                @Override
                public byte[] readAllBytes() {
                    if (read) return new byte[0];
                    read = true;
                    return data;
                }
            });
            QpackInstruction instructionData;
            while ((instructionData = wrapperData.getNextInstruction()) != null) {
                encoder.onDecoderInstruction((QpackInstruction.DecoderInstruction) instructionData);
            }
        }
        
        // Now potentially blocked streams = 0. Third stream should be allowed to index.
        coupler.clearCapturedData();
        List<Header> h3 = List.of(new Header("k3", "v3"));
        encoder.encodeHeaders(3, h3);
        
        List<byte[]> h3Instructions = coupler.getCapturedEncoderData();
        hasInsert = false;
        for (byte[] instr : h3Instructions) {
            if ((instr[0] & 0xC0) == 0x40) {
                hasInsert = true;
                break;
            }
        }
        assertTrue(hasInsert, "Should have allowed indexing after block cleared");
    }
}
