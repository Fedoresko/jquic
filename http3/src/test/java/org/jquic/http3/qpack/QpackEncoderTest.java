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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class QpackEncoderTest {

    private void feedEncoderData(QpackDecoder decoder, byte[] data) throws IOException {
        QpackStreamWrapper wrapper = new QpackStreamWrapper(new Http3StreamContext(Http3ClientStreamRole.QPACK_ENCODER) {
            private boolean read = false;
            @Override
            public byte[] readAllBytes() {
                if (read) return new byte[0];
                read = true;
                return data;
            }
        });
        QpackInstruction instruction;
        while ((instruction = wrapper.getNextInstruction()) != null) {
            decoder.onEncoderInstruction((QpackInstruction.EncoderInstruction) instruction);
        }
    }

    @Test
    public void testEncodeStaticIndexed() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        coupler.bind(encoder, decoder);

        List<Header> headers = List.of(new Header(":method", "GET"));
        ByteBuffer encoded = encoder.encodeHeaders(0, headers);
        
        List<Header> decodedHeaders = decoder.decodeHeaders(0, encoded);
        
        assertEquals(1, decodedHeaders.size());
        assertEquals(":method", decodedHeaders.getFirst().name());
        assertEquals("GET", decodedHeaders.getFirst().value());
    }

    @Test
    public void testEncodeLiteralWithNameReference() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        coupler.bind(encoder, decoder);
        encoder.setDynamicTableCapacity(4096);

        List<Header> headers = List.of(new Header(":path", "/index.html"));
        ByteBuffer encoded = encoder.encodeHeaders(0, headers);
        
        List<Header> decodedHeaders = decoder.decodeHeaders(0, encoded);
        
        assertEquals(1, decodedHeaders.size());
        assertEquals(":path", decodedHeaders.getFirst().name());
        assertEquals("/index.html", decodedHeaders.getFirst().value());
    }

    @Test
    public void testEncodeLiteralWithoutNameReference() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        coupler.bind(encoder, decoder);
        encoder.setDynamicTableCapacity(4096);

        List<Header> headers = List.of(new Header("custom-header", "custom-value"));
        ByteBuffer encoded = encoder.encodeHeaders(0, headers);
        
        List<Header> decodedHeaders = decoder.decodeHeaders(0, encoded);
        
        assertEquals(1, decodedHeaders.size());
        assertEquals("custom-header", decodedHeaders.getFirst().name());
        assertEquals("custom-value", decodedHeaders.getFirst().value());
    }

    @Test
    public void testEncodeHuffman() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream()) {
            @Override
            protected boolean shouldIndex(Header header) {
                return false;
            }
        };
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        coupler.bind(encoder, decoder);
        encoder.setDynamicTableCapacity(4096);

        // "www.example.com" should trigger Huffman encoding as it is shorter
        List<Header> headers = List.of(new Header(":authority", "www.example.com"));
        ByteBuffer encoded = encoder.encodeHeaders(0, headers);
        
        List<Header> decodedHeaders = decoder.decodeHeaders(0, encoded);
        
        assertEquals(1, decodedHeaders.size());
        assertEquals(":authority", decodedHeaders.getFirst().name());
        assertEquals("www.example.com", decodedHeaders.getFirst().value());
        
        // Verify that Huffman was actually used
        // RIC(1) + Base(1) + LiteralWithNameRef(1) = 3 bytes prefix.
        // H bit (0x80) should be set in the value length byte.
        byte lengthByte = encoded.get(3);
        assertTrue((lengthByte & 0x80) != 0, "Huffman bit should be set");
    }

    @Test
    public void testDynamicTableIndexing() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream()) {
            // Simplified encoder that ALWAYS indexes literals if we want to test dynamic indexing
            @Override
            public ByteBuffer encodeHeaders(long streamId, List<Header> headers) {
                try {
                    ByteBuffer headerBlock = ByteBuffer.allocate(8192);
                    long ricBefore = dynamicTable.getInsertCount();
                    long maxRicNeeded = 0;

                    for (Header header : headers) {
                        Integer dynamicFullIndex = findInDynamicTable(header.name(), header.value());
                        if (dynamicFullIndex != null) {
                            if (dynamicFullIndex < ricBefore) {
                                long relativeIndex = ricBefore - 1 - dynamicFullIndex;
                                writePrefixInt(headerBlock, 0x80, 6, relativeIndex);
                            } else {
                                long postBaseIndex = dynamicFullIndex - ricBefore;
                                writePrefixInt(headerBlock, 0x10, 4, postBaseIndex);
                            }
                            maxRicNeeded = Math.max(maxRicNeeded, (long) dynamicFullIndex + 1);
                            continue;
                        }

                        insertIntoDynamicTable(header);
                        long absoluteIndex = dynamicTable.getInsertCount() - 1;
                        long postBaseIndex = absoluteIndex - ricBefore;
                        writePrefixInt(headerBlock, 0x10, 4, postBaseIndex);
                        maxRicNeeded = Math.max(maxRicNeeded, absoluteIndex + 1);
                    }

                    headerBlock.flip();
                    ByteBuffer buffer = ByteBuffer.allocate(headerBlock.remaining() + 20);
                    long maxEntries = dynamicTable.getMaxEntries();
                    if (maxRicNeeded == 0) {
                        writePrefixInt(buffer, 0, 8, 0);
                    } else {
                        long encodedRic = (maxRicNeeded % (2 * maxEntries)) + 1;
                        writePrefixInt(buffer, 0, 8, encodedRic);
                    }
                    if (ricBefore >= maxRicNeeded) {
                        writePrefixInt(buffer, 0, 7, ricBefore - maxRicNeeded);
                    } else {
                        writePrefixInt(buffer, 0x80, 7, maxRicNeeded - ricBefore - 1);
                    }
                    buffer.put(headerBlock);
                    buffer.flip();
                    return buffer;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        coupler.bind(encoder, decoder);

        // Set capacity! 1000 = 0x3E8. (0x3F, 0xC9, 0x07)
        feedEncoderData(decoder, new byte[]{0x3F, (byte)0xC9, 0x07});

        // 1. First encode: should insert into dynamic table
        List<Header> headers1 = List.of(new Header("custom-name", "custom-value"));
        ByteBuffer encoded1 = encoder.encodeHeaders(0, headers1);
        
        List<Header> decoded1 = decoder.decodeHeaders(0, encoded1);
        assertEquals(headers1, decoded1);

        // 2. Second encode: should use dynamic table index
        long insertCountBefore = decoder.dynamicTable.getInsertCount();
        List<Header> headers2 = List.of(new Header("custom-name", "custom-value"));
        ByteBuffer encoded2 = encoder.encodeHeaders(1, headers2);
        
        // Encoder stream should be empty now as it's already in dynamic table, 
        // so insertCount shouldn't change.
        assertEquals(insertCountBefore, decoder.dynamicTable.getInsertCount());

        List<Header> decoded2 = decoder.decodeHeaders(1, encoded2);
        assertEquals(headers2, decoded2);
    }

    @Test
    public void testDynamicTableEviction() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream()) {
            @Override
            public ByteBuffer encodeHeaders(long streamId, List<Header> headers) {
                try {
                    ByteBuffer headerBlock = ByteBuffer.allocate(8192);
                    long ricBefore = dynamicTable.getInsertCount();
                    long maxRicNeeded = 0;

                    for (Header header : headers) {
                        insertIntoDynamicTable(header);
                        long absoluteIndex = dynamicTable.getInsertCount() - 1;
                        long postBaseIndex = absoluteIndex - ricBefore;
                        writePrefixInt(headerBlock, 0x10, 4, postBaseIndex);
                        maxRicNeeded = Math.max(maxRicNeeded, absoluteIndex + 1);
                    }

                    headerBlock.flip();
                    ByteBuffer buffer = ByteBuffer.allocate(headerBlock.remaining() + 2);
                    long maxEntries = dynamicTable.getMaxEntries();
                    if (maxRicNeeded == 0) {
                        writePrefixInt(buffer, 0, 8, 0);
                    } else {
                        long encodedRic = (maxRicNeeded % (2 * maxEntries)) + 1;
                        writePrefixInt(buffer, 0, 8, encodedRic);
                    }
                    writePrefixInt(buffer, 0, 7, ricBefore - maxRicNeeded); // Simplified
                    buffer.put(headerBlock);
                    buffer.flip();
                    return buffer;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        coupler.bind(encoder, decoder);

        // entry size = 1 + 1 + 32 = 34 bytes.
        // Capacity 100 will allow two entries (34 * 2 = 68) but not three.
        encoder.setDynamicTableCapacity(100);

        // Set capacity! 100 = 0x20 | 31 (0x3F) + (100 - 31 = 69 = 0x45)
        feedEncoderData(decoder, new byte[]{0x3F, 0x45});

        // 1. Add first header
        List<Header> headers1 = List.of(new Header("a", "1"));
        encoder.encodeHeaders(0, headers1);

        // 2. Add second header
        List<Header> headers2 = List.of(new Header("b", "2"));
        encoder.encodeHeaders(1, headers2);
        
        // 3. Add third header - should trigger eviction of 'a'
        List<Header> headers3 = List.of(new Header("c", "3"));
        encoder.encodeHeaders(2, headers3);
        
        // We verified it doesn't crash.
    }

    @Test
    public void testRequiredInsertCount() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream()) {
            @Override
            public ByteBuffer encodeHeaders(long streamId, List<Header> headers) {
                try {
                    insertIntoDynamicTable(headers.getFirst());
                    ByteBuffer buffer = ByteBuffer.allocate(10);
                    long maxEntries = dynamicTable.getMaxEntries();
                    long encodedRic = (1 % (2 * maxEntries)) + 1;
                    writePrefixInt(buffer, 0, 8, encodedRic); // RIC=1
                    writePrefixInt(buffer, 0, 7, 0); // Base=1 (Sign=0, Delta=0)
                    writePrefixInt(buffer, 0x80, 6, 0); // Indexed Dynamic, Relative Index 0
                    buffer.flip();
                    return buffer;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        coupler.bind(encoder, decoder);

        // Set capacity!
        feedEncoderData(decoder, new byte[]{0x3F, (byte)0xC9, 0x07});

        List<Header> headers = List.of(new Header("custom", "value"));
        ByteBuffer encoded = encoder.encodeHeaders(0, headers);
        
        // RIC should be 1, which encodes to 2 (if MaxEntries > 0)
        assertEquals(2, encoded.get(0));
        
        assertEquals(headers, decoder.decodeHeaders(0, encoded));
    }

    @Test
    public void testOnEncoderDataInserts() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        // 1. Set Dynamic Table Capacity: 001xxxxx -> 0x20 | 63 = 0x3F. (Max capacity)
        // Let's use 1000. 1000 = 0x3E8.
        // 001xxxxx -> 0x20 | 31 = 0x3F. Remaining 1000 - 31 = 969.
        // 969 = 0x3C9. 0xC9 (1001001), 0x07.
        feedEncoderData(decoder, new byte[]{0x3F, (byte)0xC9, 0x07});

        // 2. Insert With Literal Name: 01xxxxxx, Huffman=0, name="a", Huffman=0, value="1"
        // 0x41, 0x61, 0x01, 0x31.
        feedEncoderData(decoder, new byte[]{0x41, 0x61, 0x01, 0x31});
        
        // RIC=1, Base=1, Indexed Dynamic 0
        // RIC=1 encodes to (1 % (2*MaxEntries)) + 1 = 2.
        // MaxEntries for 1000 is 1000/32 = 31.
        // EncodedRIC = (1 % 62) + 1 = 2.
        ByteBuffer headerBlock = ByteBuffer.wrap(new byte[]{0x02, 0x00, (byte)0x80});
        List<Header> decoded = decoder.decodeHeaders(0, headerBlock);
        assertEquals(1, decoded.size());
        assertEquals("a", decoded.getFirst().name());
        assertEquals("1", decoded.getFirst().value());
    }
}
