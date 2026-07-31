/*
 * Copyright 2026 Fedor Malyshev
 *
 * Licensed under the Apache License, Version 2.0 (the "License") ;
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
