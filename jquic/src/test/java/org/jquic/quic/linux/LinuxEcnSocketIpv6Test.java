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
package org.jquic.quic.linux;

import org.junit.jupiter.api.Test;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class LinuxEcnSocketIpv6Test {

    @Test
    public void testBuildSockAddrIpv6() throws Exception {
        Arena arena = Arena.ofConfined();
        // Updated size: 28 bytes per address
        MemorySegment batchAddrs = arena.allocate(28 * 128); 
        
        // Mocking IPv4 behavior with new size
        byte[] ipv4 = new byte[] {127, 0, 0, 1};
        int port = 12345;
        int idx = 0;
        int pos = idx * 28;
        
        batchAddrs.set(ValueLayout.JAVA_SHORT, pos, (short) 2); // AF_INET
        batchAddrs.set(ValueLayout.JAVA_SHORT, pos + 2, Short.reverseBytes((short) port));
        batchAddrs.set(ValueLayout.JAVA_BYTE, pos + 4, ipv4[0]);
        batchAddrs.set(ValueLayout.JAVA_BYTE, pos + 5, ipv4[1]);
        batchAddrs.set(ValueLayout.JAVA_BYTE, pos + 6, ipv4[2]);
        batchAddrs.set(ValueLayout.JAVA_BYTE, pos + 7, ipv4[3]);
        
        assertEquals((short) 2, batchAddrs.get(ValueLayout.JAVA_SHORT, pos));
        assertEquals((short) 12345, Short.reverseBytes(batchAddrs.get(ValueLayout.JAVA_SHORT, pos + 2)));
        assertEquals((byte) 127, batchAddrs.get(ValueLayout.JAVA_BYTE, pos + 4));

        // IPv6 test
        byte[] ipv6 = InetAddress.getByName("::1").getAddress();
        assertEquals(16, ipv6.length);
        
        idx = 1;
        pos = idx * 28;
        
        // AF_INET6 = 10
        batchAddrs.set(ValueLayout.JAVA_SHORT, pos, (short) 10);
        // Port
        batchAddrs.set(ValueLayout.JAVA_SHORT, pos + 2, Short.reverseBytes((short) port));
        // flowinfo
        batchAddrs.set(ValueLayout.JAVA_INT, pos + 4, 0);
        // addr
        for (int i = 0; i < 16; i++) {
            batchAddrs.set(ValueLayout.JAVA_BYTE, pos + 8 + i, ipv6[i]);
        }
        // scope_id
        batchAddrs.set(ValueLayout.JAVA_INT, pos + 24, 0);

        assertEquals((short) 10, batchAddrs.get(ValueLayout.JAVA_SHORT, pos));
        assertEquals((short) 12345, Short.reverseBytes(batchAddrs.get(ValueLayout.JAVA_SHORT, pos + 2)));
        for (int i = 0; i < 16; i++) {
            assertEquals(ipv6[i], batchAddrs.get(ValueLayout.JAVA_BYTE, pos + 8 + i));
        }
    }
}
