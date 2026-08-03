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
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

public class QpackDynamicDecoderTest {

    @Test
    public void testDynamicTableInsertAndIndexed() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream()) {
            @Override
            protected void insertCountIncrement(long increment) {}
        };
        coupler.bind(encoder, decoder);
        
        // 0. Set capacity
        ByteBuffer capacityData = ByteBuffer.allocate(10);
        capacityData.put((byte) 0x3F); // Set Capacity, prefix 5, value 1000
        capacityData.put((byte) 0xE9); // 1000 - 31 = 969. 969 = 0x3C9. 
        // Wait, 969 in varint: 969 = 7 * 128 + 73. 
        // Actually let's use a simpler value. 128. 128-31=97.
        capacityData.clear();
        capacityData.put((byte) 0x3F);
        capacityData.put((byte) 0x61); // 31 + 97 = 128.
        capacityData.flip();
        decoder.onEncoderData(capacityData);

        // 1. Encoder instruction: Insert With Literal Name "custom-key", "custom-value"
        // 01nnnnnn -> prefix 6. No, it's 01Hnnnnn -> prefix 5. 
        // 0x4A: 0100 1010. H=0, n=10.
        ByteBuffer encoderData = ByteBuffer.allocate(100);
        encoderData.put((byte) 0x4A); 
        encoderData.put("custom-key".getBytes());
        encoderData.put((byte) 0x0C); // length 12
        encoderData.put("custom-value".getBytes());
        encoderData.flip();
        
        decoder.onEncoderData(encoderData);
        
        // 2. Decode header block using the dynamic entry
        // RIC=1. Capacity is 128, so MaxEntries = 4, FullRange = 8.
        // EncodedRIC = (1 % 8) + 1 = 2.
        
        ByteBuffer headerBlock = ByteBuffer.allocate(10);
        headerBlock.put((byte) 0x02); // Encoded RIC=2 (Actual RIC=1)
        headerBlock.put((byte) 0x00); // Base=1 (Sign=0, Delta=0 -> Base = 1 + 0 = 1)
        headerBlock.put((byte) 0x80); // Indexed Dynamic, Relative Index 0 -> Absolute = 1 - 0 - 1 = 0
        headerBlock.flip();
        
        List<Header> headers = decoder.decodeHeaders(0, headerBlock);
        assertEquals(1, headers.size());
        assertEquals("custom-key", headers.getFirst().name());
        assertEquals("custom-value", headers.getFirst().value());
    }

    @Test
    public void testInsertWithNameReference() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream()) {
            @Override
            protected void insertCountIncrement(long increment) {}
        };
        coupler.bind(encoder, decoder);
        
        // 0. Set capacity
        ByteBuffer capacityData = ByteBuffer.allocate(10);
        capacityData.put((byte) 0x3F);
        capacityData.put((byte) 0x61); 
        capacityData.flip();
        decoder.onEncoderData(capacityData);

        // 1. Insert ":method", "PUT" (Static name reference index 17 - :method)
        // 1Tnnnnnn -> T=1, index 17 -> 1101 0001 = 0xD1
        ByteBuffer encoderData = ByteBuffer.allocate(100);
        encoderData.put((byte) 0xD1);
        encoderData.put((byte) 0x03); // length 3
        encoderData.put("PUT".getBytes());
        encoderData.flip();
        
        decoder.onEncoderData(encoderData);
        
        // 2. Decode header block
        // RIC=1, Base=1. Capacity 128 -> MaxEntries 4 -> EncodedRIC = 2.
        // Indexed Dynamic Index 0 -> 0x80
        ByteBuffer headerBlock2 = ByteBuffer.allocate(10);
        headerBlock2.put((byte) 0x02);
        headerBlock2.put((byte) 0x00);
        headerBlock2.put((byte) 0x80);
        headerBlock2.flip();
        
        List<Header> headers2 = decoder.decodeHeaders(0, headerBlock2);
        assertEquals(1, headers2.size());
        assertEquals(":method", headers2.getFirst().name());
        assertEquals("PUT", headers2.getFirst().value());
    }

    @Test
    public void testPostBaseIndexing() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream()) {
            @Override
            protected void insertCountIncrement(long increment) {}
        };
        coupler.bind(encoder, decoder);
        
        // 0. Set capacity
        ByteBuffer capacityData = ByteBuffer.allocate(10);
        capacityData.put((byte) 0x3F);
        capacityData.put((byte) 0x61); 
        capacityData.flip();
        decoder.onEncoderData(capacityData);

        // 1. Insert "k1", "v1"
        ByteBuffer encoderData = ByteBuffer.allocate(100);
        encoderData.put((byte) 0x42); 
        encoderData.put("k1".getBytes());
        encoderData.put((byte) 0x02);
        encoderData.put("v1".getBytes());
        encoderData.flip();
        decoder.onEncoderData(encoderData);
        
        // 2. Header Block with Base=0 (RIC=1, Sign=1 (-), Delta=0 -> Base = 1 - 0 - 1 = 0)
        // Capacity 128 -> MaxEntries 4 -> EncodedRIC = 2.
        // Indexed Post-Base Index 0 -> 0001 0000 = 0x10 -> Absolute = 0 + 0 = 0
        ByteBuffer headerBlock3 = ByteBuffer.allocate(10);
        headerBlock3.put((byte) 0x02);
        headerBlock3.put((byte) 0x80); // Sign=1, Delta=0
        headerBlock3.put((byte) 0x10); // Post-base index 0
        headerBlock3.flip();
        
        List<Header> headers3 = decoder.decodeHeaders(0, headerBlock3);
        assertEquals(1, headers3.size());
        assertEquals("k1", headers3.getFirst().name());
        assertEquals("v1", headers3.getFirst().value());
    }

    @Test
    public void testEviction() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream()) {
            @Override
            protected void insertCountIncrement(long increment) {}
        };
        coupler.bind(encoder, decoder);
        
        // Set capacity to 40 (entry size = 4 + 4 + 32 = 40)
        ByteBuffer encoderData = ByteBuffer.allocate(100);
        encoderData.put((byte) 0x3F); // 0011 1111 -> Set Capacity, prefix 5, 31+9=40
        encoderData.put((byte) 0x09);
        
        // Insert "k1", "v1" (size 2+2+32 = 36)
        encoderData.put((byte) 0x42);
        encoderData.put("k1".getBytes());
        encoderData.put((byte) 0x02);
        encoderData.put("v1".getBytes());
        
        // Insert "k2", "v2" (size 36) -> should evict k1
        encoderData.put((byte) 0x42);
        encoderData.put("k2".getBytes());
        encoderData.put((byte) 0x02);
        encoderData.put("v2".getBytes());
        encoderData.flip();
        
        decoder.onEncoderData(encoderData);
        
        // Try to access absolute index 0 (k1) - should fail
        // Capacity 40 -> MaxEntries 1 -> FullRange 2.
        // RIC=2 -> EncodedRIC = (2 % 2) + 1 = 1.
        ByteBuffer headerBlock4 = ByteBuffer.allocate(10);
        headerBlock4.put((byte) 0x01); // Encoded RIC=1 (Actual RIC=2)
        headerBlock4.put((byte) 0x00); // Base=2
        headerBlock4.put((byte) 0x81); // Relative index 1 -> Absolute = 2 - 1 - 1 = 0
        headerBlock4.flip();
        
        assertThrows(IOException.class, () -> decoder.decodeHeaders(0, headerBlock4));
        
        // Access absolute index 1 (k2) - should work
        headerBlock4.clear();
        headerBlock4.put((byte) 0x01); // Encoded RIC=1
        headerBlock4.put((byte) 0x00);
        headerBlock4.put((byte) 0x80); // Relative index 0 -> Absolute = 2 - 0 - 1 = 1
        headerBlock4.flip();
        
        List<Header> headers4 = decoder.decodeHeaders(0, headerBlock4);
        assertEquals(1, headers4.size());
        assertEquals("k2", headers4.getFirst().name());
    }
}
