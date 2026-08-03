package org.jquic.http3.qpack;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class QpackSpyTest {

    @Test
    public void testSpyingEncoderInstructions() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        coupler.bind(encoder, decoder);

        // 1. Set capacity
        encoder.setDynamicTableCapacity(1024);
        
        List<byte[]> encoderData = coupler.getCapturedEncoderData();
        assertEquals(1, encoderData.size(), "Should have captured 1 instruction (Set Capacity)");
        // 001xxxxx -> 0x20 | ...
        assertEquals(0x20, (encoderData.getFirst()[0] & 0xE0), "Should be Set Dynamic Table Capacity instruction");

        // 2. Encode header that triggers indexing
        coupler.clearCapturedData();
        List<Header> headers = List.of(new Header("custom-key", "custom-value"));
        encoder.encodeHeaders(0, headers);

        encoderData = coupler.getCapturedEncoderData();
        assertEquals(1, encoderData.size(), "Should have captured 1 instruction (Insert With Literal Name)");
        // 01xxxxxx -> 0x40 | ...
        assertEquals(0x40, (encoderData.getFirst()[0] & 0xC0), "Should be Insert With Literal Name instruction");
        
        // 3. Verify decoder automatically sent Insert Count Increment
        List<byte[]> decoderData = coupler.getCapturedDecoderData();
        assertEquals(1, decoderData.size(), "Should have captured 1 decoder instruction (Insert Count Increment)");
        // 00nnnnnn -> 0x01 (increment 1)
        assertEquals(0x01, decoderData.getFirst()[0], "Should be Insert Count Increment = 1");
    }

    @Test
    public void testSpyingDecoderAcks() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream());
        coupler.bind(encoder, decoder);

        // 1. Encode something on stream 5 so there's something to acknowledge
        encoder.encodeHeaders(5, List.of(new Header(":method", "GET")));
        coupler.clearCapturedData();

        // 2. Manual acknowledgment via decoder stream (simulating what Http3ConnectionHandler does)
        java.io.DataOutputStream decoderStream = coupler.getDecoderStream();
        
        // Section Acknowledgment: 1xxxxxxx, stream 5 -> 0x85
        decoderStream.write(0x85);
        decoderStream.flush();

        List<byte[]> decoderData = coupler.getCapturedDecoderData();
        assertEquals(1, decoderData.size());
        assertEquals(0x85, decoderData.getFirst()[0] & 0xFF);
    }
}
