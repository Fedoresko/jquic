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

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class QpackDecoderTest {

    @Test
    public void testDecodeStaticIndexed() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        // RFC 9204 example or simple manual encoding
        // Required Insert Count = 0 (1 byte: 0x00)
        // Base = 0 (1 byte: 0x00)
        // Indexed Header Field: static index 17 (:method: GET) -> 1Txxxxxx where T=1, index=17 -> 11010001 = 0xD1
        byte[] data = new byte[] { 0x00, 0x00, (byte) 0xD1 };
        ByteBuffer buffer = ByteBuffer.wrap(data);

        List<Header> headers = decoder.decodeHeaders(0, buffer);
        assertEquals(1, headers.size());
        assertEquals(":method", headers.getFirst().name());
        assertEquals("GET", headers.getFirst().value());
    }

    @Test
    public void testDecodeLiteralWithNameReference() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        // Required Insert Count = 0 (0x00)
        // Base = 0 (0x00)
        // Literal Header Field With Name Reference: 01NTxxxx
        // N=1 (don't add to dynamic table - wait, in Decoder it's actually 01xx xxxx for Literal with Name Ref)
        // Section 4.5.4: 01NTxxxx. T=1 (static), index=21 (:method: GET) - wait, let's use index 1 (:path: /)
        // index 1: 01010001 = 0x51
        // Value "index.html", not Huffman: length 10 (0x0A), then bytes
        String value = "index.html";
        byte[] valueBytes = value.getBytes();
        ByteBuffer buffer = ByteBuffer.allocate(3 + 1 + valueBytes.length);
        buffer.put((byte) 0x00); // RIC
        buffer.put((byte) 0x00); // Base
        buffer.put((byte) 0x51); // Literal with Name Ref, Static, Index 1
        buffer.put((byte) 0x0A); // Value length 10, no Huffman
        buffer.put(valueBytes);
        buffer.flip();

        List<Header> headers = decoder.decodeHeaders(0, buffer);
        assertEquals(1, headers.size());
        assertEquals(":path", headers.getFirst().name());
        assertEquals("index.html", headers.getFirst().value());
    }
    @Test
    public void testDecodeLiteralWithoutNameReference() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        // Required Insert Count = 0 (0x00)
        // Base = 0 (0x00)
        // Literal Header Field Without Name Reference: 001Nxxxx
        // N=0 (no Huffman for name), xxxx=4 (name length)
        // Name: "host" (4 bytes)
        // Value: "localhost", no Huffman: length 9 (0x09)
        byte[] name = "host".getBytes();
        byte[] value = "localhost".getBytes();
        ByteBuffer buffer = ByteBuffer.allocate(2 + 1 + name.length + 1 + value.length);
        buffer.put((byte) 0x00); // RIC
        buffer.put((byte) 0x00); // Base
        buffer.put((byte) 0x24); // 0010 0100 -> N=0, length 4
        buffer.put(name);
        buffer.put((byte) 0x09); // length 9, no Huffman
        buffer.put(value);
        buffer.flip();

        List<Header> headers = decoder.decodeHeaders(0, buffer);
        assertEquals(1, headers.size());
        assertEquals("host", headers.getFirst().name());
        assertEquals("localhost", headers.getFirst().value());
    }

    @Test
    public void testDecodeHuffman() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        // RIC=0, Base=0
        // Literal With Name Ref, Huffman for value
        // ":authority" is index 0 in static table
        // 01NTxxxx -> T=1, static index 0 -> 01010000 = 0x50
        // "www.example.com" Huffman: 0x8c (H=1, len=12) 0xf1e3c2e5f23a6ba0ab90f4ff
        QpackEncoder build = new QpackEncoder(null);
        ByteBuffer byteBuffer = build.encodeHeaders(0, List.of(new Header(":authority", "www.example.com"))).flip();
        System.out.println("RES: "+ HexFormat.of().formatHex(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit()));

        byte[] huffmanValue = new byte[] { (byte)0xf1, (byte)0xe3, (byte)0xc2, (byte)0xe5, (byte)0xf2, (byte)0x3a, (byte)0x6b, (byte)0xa0, (byte)0xab, (byte)0x90, (byte)0xf4, (byte)0xff };
        ByteBuffer buffer = ByteBuffer.allocate(2 + 1 + 1 + huffmanValue.length);
        buffer.put((byte) 0x00);
        buffer.put((byte) 0x00);
        buffer.put((byte) 0x50);
        buffer.put((byte) 0x8C); // H=1, length 12
        buffer.put(huffmanValue);
        buffer.flip();

        List<Header> headers = decoder.decodeHeaders(0, buffer);
        assertEquals(1, headers.size());
        assertEquals(":authority", headers.getFirst().name());
        assertEquals("www.example.com", headers.getFirst().value());
    }

    @Test
    public void testStreamCancellationOnClose() throws Exception {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        java.io.DataOutputStream dos = new java.io.DataOutputStream(baos);
        QpackDecoder decoder = new QpackDecoder(dos);

        // Record some active streams
        decoder.decodeHeaders(1, ByteBuffer.wrap(new byte[]{0, 0, (byte)0xD1}));
        decoder.decodeHeaders(64, ByteBuffer.wrap(new byte[]{0, 0, (byte)0xD1}));

        decoder.close();

        byte[] output = baos.toByteArray();
        // Stream 1: 0x40 | 1 = 0x41
        // Stream 64: 0x40 | 63 = 0x7F, then 64-63=1 -> 0x01
        // Total bytes expected: 0x41, 0x7F, 0x01
        assertArrayEquals(new byte[]{0x41, 0x7F, 0x01}, output);
    }
}
