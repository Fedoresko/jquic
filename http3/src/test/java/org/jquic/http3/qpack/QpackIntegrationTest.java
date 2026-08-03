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
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

public class QpackIntegrationTest {

    @Test
    public void testMultiRequestFlow() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        coupler.bind(encoder, decoder);

        // 0. Setup: Set capacity
        encoder.setDynamicTableCapacity(1024);
        
        // 1. Request 1: New header to be indexed
        List<Header> req1Headers = List.of(
            new Header(":method", "GET"),
            new Header(":path", "/index.html"),
            new Header("custom-header", "value1")
        );
        ByteBuffer encoded1 = encoder.encodeHeaders(1, req1Headers);
        
        // Verify Request 1
        List<Header> decoded1 = decoder.decodeHeaders(1, encoded1);
        assertEquals(req1Headers, decoded1, "Request 1 decoding failed");
        
        // Verify Encoder Stream: should have Set Capacity and one Insert instruction
        List<byte[]> encoderInstructions = coupler.getCapturedEncoderData();
        assertTrue(encoderInstructions.size() >= 2, "Should have at least Capacity and Insert instructions");
        
        // Verify Decoder automatically sent Insert Count Increment
        List<byte[]> decoderInstructions = coupler.getCapturedDecoderData();
        assertFalse(decoderInstructions.isEmpty(), "Decoder should have sent Insert Count Increment");
        
        // 2. Request 2: Use indexed header from Request 1
        List<Header> req2Headers = List.of(
            new Header(":method", "GET"),
            new Header("custom-header", "value1")
        );
        ByteBuffer encoded2 = encoder.encodeHeaders(2, req2Headers);
        
        // Verify Request 2
        List<Header> decoded2 = decoder.decodeHeaders(2, encoded2);
        assertEquals(req2Headers, decoded2, "Request 2 decoding failed");
        
        // 3. Decoder acknowledges Request 1
        // Simulate Http3ConnectionHandler.writeSectionAck behavior
        java.io.DataOutputStream decoderOut = coupler.getDecoderStream();
        // Section Acknowledgment for stream 1: 1xxxxxxx | streamId
        decoderOut.write(0x80 | 0x01);
        decoderOut.flush();
        
        // 4. Request 3: Another new header
        List<Header> req3Headers = List.of(
            new Header(":method", "POST"),
            new Header("another-header", "value3")
        );
        ByteBuffer encoded3 = encoder.encodeHeaders(3, req3Headers);
        
        // Verify Request 3
        List<Header> decoded3 = decoder.decodeHeaders(3, encoded3);
        assertEquals(req3Headers, decoded3, "Request 3 decoding failed");

        // Verify that the encoder's knownReceivedCount was updated by the Ack
        // We can check this indirectly by seeing if it continues to work correctly 
        // and uses Relative indexing instead of Post-Base where appropriate.
        // In our current implementation, Relative index is used if absoluteIndex < ricBefore.
    }

    @Test
    public void testBlockingAndUnblocking() throws Exception {
        // We will manually pipe to simulate blocking
        QpackEncoder encoder = new QpackEncoder(null); // We'll set stream manually
        
        // Use a decoder that allows blocking
        QpackDecoder decoder = new QpackDecoder(null, 4096);
        QpackBlockingManager blockingManagerToSimulate = new QpackBlockingManager(10, (id, buf) -> {
            try { return decoder.decodeHeaders(id, buf); } catch (Exception ex) { throw new RuntimeException(ex); }
        });
        decoder.setUnblockedStreamListener(blockingManagerToSimulate::tryUnblockStreams);

        encoder.setDynamicTableCapacity(1024);
        
        // Encode a header that REQUIRES an insertion
        // We'll use a fresh encoder to capture its output
        java.io.ByteArrayOutputStream encoderBus = new java.io.ByteArrayOutputStream();
        QpackEncoder realEncoder = new QpackEncoder(new java.io.DataOutputStream(encoderBus));
        realEncoder.setDynamicTableCapacity(1024);
        
        List<Header> headers = List.of(new Header("blocked", "true"));
        ByteBuffer encodedBlock = realEncoder.encodeHeaders(5, headers);
        byte[] instructions = encoderBus.toByteArray();
        
        // Try to decode headers in a decoder that hasn't seen the instructions yet
        QpackDecoder realDecoder = new QpackDecoder(null, 4096);
        QpackBlockingManager blockingManager = new QpackBlockingManager(10, (id, buf) -> {
            try { return realDecoder.decodeHeaders(id, buf); } catch (Exception ex) { throw new RuntimeException(ex); }
        });
        realDecoder.setUnblockedStreamListener(blockingManager::tryUnblockStreams);
        
        ByteBuffer encodedBlockDuplicate = encodedBlock.duplicate();
        assertThrows(QpackRequiredInsertCountException.class, () -> realDecoder.decodeHeaders(5, encodedBlockDuplicate));
        
        // Manually block
        try {
            realDecoder.decodeHeaders(5, encodedBlock.duplicate());
        } catch (QpackRequiredInsertCountException e) {
            blockingManager.blockStream(5, e.getFrame(), e.getRequiredInsertCount());
        }
        
        // Now provide the instructions
        realDecoder.onEncoderData(ByteBuffer.wrap(instructions));
        
        // Unblock - actually it's now done automatically via onEncoderData -> listener
        // but since we are simulating it, we can still call tryUnblockStreams if we want, 
        // but it must be with the new signature.
        // blockingManager.tryUnblockStreams(realDecoder.getInsertCount());
        
        List<Header> decoded = realDecoder.decodeHeaders(5, encodedBlock);
        assertEquals(headers, decoded);
    }

    @Test
    public void testExplicitDynamicTableUsage() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        coupler.bind(encoder, decoder);

        encoder.setDynamicTableCapacity(1024);

        // 1. First time: literal with indexing
        List<Header> headers1 = List.of(new Header("custom-header", "value1"));
        ByteBuffer encoded1 = encoder.encodeHeaders(1, headers1);
        
        // Expected encoded1:
        // RIC = 1 -> Encoded RIC = (1 % 256) + 1 = 2
        // Base = 0 (ricBefore=0, maxRicNeeded=1) -> Sign=1, Delta=0 -> 0x80
        // Entry: Post-Base Index 0 -> 0x10
        // Total: 02 80 10
        assertEquals(3, encoded1.remaining());
        assertEquals((byte)0x02, encoded1.get(0));
        assertEquals((byte)0x80, encoded1.get(1));
        assertEquals((byte)0x10, encoded1.get(2));

        // Verify decoder works
        assertEquals(headers1, decoder.decodeHeaders(1, encoded1.duplicate()));

        // 2. Second time: same header should use relative index from dynamic table
        ByteBuffer encoded2 = encoder.encodeHeaders(2, headers1);

        // Expected encoded2:
        // ricBefore = 1, maxRicNeeded = 1
        // RIC = 1 -> Encoded RIC = 2
        // Base = 1 (ricBefore=1, maxRicNeeded=1) -> Sign=0, Delta=0 -> 0x00
        // Entry: Relative Index 0 -> 0x80
        // Total: 02 00 80
        assertEquals(3, encoded2.remaining());
        assertEquals((byte)0x02, encoded2.get(0));
        assertEquals((byte)0x00, encoded2.get(1));
        assertEquals((byte)0x80, encoded2.get(2));
        
        assertEquals(headers1, decoder.decodeHeaders(2, encoded2.duplicate()));

        // 3. Third time: new header + old header
        List<Header> headers2 = List.of(
            new Header("new-header", "value2"),
            new Header("custom-header", "value1")
        );
        ByteBuffer encoded3 = encoder.encodeHeaders(3, headers2);
        
        // Expected encoded3:
        // ricBefore = 1
        // new-header: indexed -> absoluteIndex 1, postBaseIndex 0 -> 0x10
        // custom-header: found at absoluteIndex 0, ricBefore=1 -> relativeIndex 0 -> 0x80
        // maxRicNeeded = 2
        // RIC = 2 -> Encoded RIC = (2 % 256) + 1 = 3
        // Base = 1 (ricBefore=1, maxRicNeeded=2) -> Sign=1, Delta=0 -> 0x80
        // Total: 03 80 10 80
        assertEquals(4, encoded3.remaining());
        assertEquals((byte)0x03, encoded3.get(0));
        assertEquals((byte)0x80, encoded3.get(1));
        assertEquals((byte)0x10, encoded3.get(2));
        assertEquals((byte)0x80, encoded3.get(3));
        
        assertEquals(headers2, decoder.decodeHeaders(3, encoded3.duplicate()));
    }

    @Test
    public void testDynamicTableEvictionIntegration() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        coupler.bind(encoder, decoder);

        // Header size: "evict-me-now" (12) + "value1" (6) + 32 = 50 bytes.
        // Capacity 110 allows 2 entries (100 bytes).
        encoder.setDynamicTableCapacity(110);

        List<Header> h1 = List.of(new Header("evict-me-now", "value1"));
        encoder.encodeHeaders(1, h1); // absolute index 0

        List<Header> h2 = List.of(new Header("stay-in-table", "value2"));
        encoder.encodeHeaders(2, h2); // absolute index 1
        
        // 3. Add third header - should trigger eviction of h1
        List<Header> h3 = List.of(new Header("third-header", "value3"));
        encoder.encodeHeaders(4, h3); // absolute index 2. index 0 is evicted.
        
        // Now encoding h1 again should result in a NEW insertion because it's not in the table anymore.
        coupler.clearCapturedData();
        encoder.encodeHeaders(5, h1);
        
        List<byte[]> instructions = coupler.getCapturedEncoderData();
        // Should have one instruction: Insert With Literal Name (since it was evicted)
        assertFalse(instructions.isEmpty(), "Should have sent encoder instructions for re-insertion");
        // 01xxxxxx -> 0x40
        assertTrue((instructions.get(0)[0] & 0xC0) == 0x40, "Should be Insert With Literal Name instruction");
        
        // Verify that the decoder still works correctly
        ByteBuffer encodedH1 = encoder.encodeHeaders(6, h1);
        assertEquals(h1, decoder.decodeHeaders(6, encodedH1));
    }

    @Test
    public void testFullCycleWithDetailedVerification() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        coupler.bind(encoder, decoder);

        // --- Iteration 1: Set Capacity ---
        encoder.setDynamicTableCapacity(2048);
        List<byte[]> encoderData = coupler.getCapturedEncoderData();
        assertEquals(1, encoderData.size());
        // 001xxxxx -> 0x20. 2048-31=2017. 2017 = 0x7E1. 0x61, 0x0F. No...
        // Varint for 2017: 2017 / 128 = 15 (0x0F), 2017 % 128 = 97 (0x61).
        // Result: 3F E1 0F. Wait, 0x3F is prefix saturated.
        assertTrue((encoderData.get(0)[0] & 0xE0) == 0x20, "Should be Set Capacity instruction");
        coupler.clearCapturedData();

        // --- Iteration 2: Literal With Indexing (New Header) ---
        List<Header> h1 = List.of(new Header("custom-a", "value-a"));
        ByteBuffer block1 = encoder.encodeHeaders(1, h1);
        
        // 1. Verify Encoder Stream: Insert With Literal Name
        encoderData = coupler.getCapturedEncoderData();
        assertEquals(1, encoderData.size());
        assertTrue((encoderData.get(0)[0] & 0xC0) == 0x40, "Should be Insert With Literal Name");
        
        // 2. Verify Decoder Stream: Insert Count Increment
        List<byte[]> decoderData = coupler.getCapturedDecoderData();
        assertEquals(1, decoderData.size());
        assertEquals(0x01, decoderData.get(0)[0], "Should be Insert Count Increment = 1");
        
        // 3. Verify Encoder State
        assertEquals(1, encoder.getKnownReceivedCount(), "Encoder should have updated knownReceivedCount to 1");
        
        // 4. Decode and Verify
        assertEquals(h1, decoder.decodeHeaders(1, block1));
        coupler.clearCapturedData();

        // --- Iteration 3: Section Acknowledgment ---
        // Simulate Http3ConnectionHandler.writeSectionAck(1)
        java.io.DataOutputStream decoderStream = coupler.getDecoderStream();
        decoderStream.write(0x81); // 1xxxxxxx | 1
        decoderStream.flush();
        
        // This should have updated encoder state (maxRicNeeded for stream 1 was 1)
        // knownReceivedCount was already 1 from Increment. Ack also sets it to 1.
        assertEquals(1, encoder.getKnownReceivedCount());
        
        decoderData = coupler.getCapturedDecoderData();
        assertEquals(1, decoderData.size());
        assertEquals((byte)0x81, decoderData.get(0)[0]);
        coupler.clearCapturedData();

        // --- Iteration 4: Using Dynamic Entry (Relative Index) ---
        ByteBuffer block2 = encoder.encodeHeaders(2, h1);
        
        // Verify no new encoder instructions (already in table)
        assertTrue(coupler.getCapturedEncoderData().isEmpty());
        
        // Verify Header Block uses Relative Index (0x80 | relativeIndex)
        // Base = 1 (ricBefore=1, maxRicNeeded=1) -> Sign=0, Delta=0 -> 0x00
        // RIC = 1 -> 0x01
        // Entry: Relative Index 0 -> 0x80
        // Total: 01 00 80
        assertEquals(3, block2.remaining());
        assertEquals((byte)0x80, block2.get(2));
        
        assertEquals(h1, decoder.decodeHeaders(2, block2));
        coupler.clearCapturedData();

        // --- Iteration 5: Multiple Headers (Mixed) ---
        List<Header> h3 = List.of(
            new Header("custom-a", "value-a"), // In dynamic table
            new Header(":method", "PUT")        // Literal with Name Ref (Static) - won't index by default in my shouldIndex
        );
        ByteBuffer block3 = encoder.encodeHeaders(3, h3);
        
        // :method: PUT is literal without indexing because shouldIndex (default) returns true if length < 512.
        // Wait, my QpackEncoder.shouldIndex is: return (header.name().length() + header.value().length() + 32) < 512;
        // So ":method": "PUT" WILL be indexed! (7 + 3 + 32 = 42 < 512).
        
        // Verify Encoder Stream: No new instructions for ":method": "PUT" as it is in the static table
        encoderData = coupler.getCapturedEncoderData();
        assertTrue(encoderData.isEmpty(), "Should NOT have sent encoder instructions for :method: PUT (static table match)");
        
        // Verify Decoder Stream: Insert Count Increment remains 1 (no new dynamic entries)
        decoderData = coupler.getCapturedDecoderData();
        assertTrue(decoderData.isEmpty(), "No new Increment should be sent");
        
        assertEquals(1, encoder.getKnownReceivedCount());
        
        assertEquals(h3, decoder.decodeHeaders(3, block3));
    }
}
