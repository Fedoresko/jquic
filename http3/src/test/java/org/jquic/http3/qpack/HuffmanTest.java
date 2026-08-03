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

import static org.junit.jupiter.api.Assertions.assertEquals;

public class HuffmanTest {

    @Test
    public void testDecodeExample1() {
        // "www.example.com"
        // HPACK Appendix C.4.1: f1e3 c2e5 f23a 6ba0 ab90 f4ff
        byte[] encoded = new byte[] {
            (byte) 0xf1, (byte) 0xe3, (byte) 0xc2, (byte) 0xe5, (byte) 0xf2, (byte) 0x3a,
            (byte) 0x6b, (byte) 0xa0, (byte) 0xab, (byte) 0x90, (byte) 0xf4, (byte) 0xff
        };
        byte[] decoded = Huffman.decode(ByteBuffer.wrap(encoded));
        assertEquals("www.example.com", new String(decoded));
    }

    @Test
    public void testDecodeSimpleExample1()  {
        byte[] encoded = new byte[] {0x1c, 0x63};
        byte[] decoded = Huffman.decode(ByteBuffer.wrap(encoded));
        assertEquals("aba", new String(decoded));
    }

    @Test
    public void testDecodeExample2() {
        // "no-cache"
        // HPACK Appendix C.6.1: a8eb 1064 9cbf
        byte[] encoded = new byte[] {
            (byte) 0xa8, (byte) 0xeb, (byte) 0x10, (byte) 0x64, (byte) 0x9c, (byte) 0xbf
        };
        byte[] decoded = Huffman.decode(ByteBuffer.wrap(encoded));
        assertEquals("no-cache", new String(decoded));
    }

    @Test
    public void testDecodeExample3() {
        // "custom-key"
        // HPACK Appendix C.6.1: 25a8 49e9 5ba9 7d7f
        byte[] encoded = new byte[] {
            (byte) 0x25, (byte) 0xa8, (byte) 0x49, (byte) 0xe9, (byte) 0x5b, (byte) 0xa9, (byte) 0x7d, (byte) 0x7f
        };
        byte[] decoded = Huffman.decode(ByteBuffer.wrap(encoded));
        assertEquals("custom-key", new String(decoded));
    }
}
