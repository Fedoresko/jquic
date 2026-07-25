package org.jquic.http3;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class Http3StreamRoleTest {

    @Test
    void testClientFromStreamType() {
        assertEquals(Http3ClientStreamRole.CONTROL, Http3ClientStreamRole.fromStreamType(0x00));
        assertEquals(Http3ClientStreamRole.QPACK_ENCODER, Http3ClientStreamRole.fromStreamType(0x02));
        assertEquals(Http3ClientStreamRole.QPACK_DECODER, Http3ClientStreamRole.fromStreamType(0x03));

        // Grease types
        assertEquals(Http3ClientStreamRole.GREASE, Http3ClientStreamRole.fromStreamType(0x21));
        assertEquals(Http3ClientStreamRole.GREASE, Http3ClientStreamRole.fromStreamType(0x40));

        // Unknown type
        assertEquals(Http3ClientStreamRole.UNKNOWN, Http3ClientStreamRole.fromStreamType(0xFF));
        assertEquals(Http3ClientStreamRole.UNKNOWN, Http3ClientStreamRole.fromStreamType(0x01)); // PUSH is not for client-initiated
    }
}
