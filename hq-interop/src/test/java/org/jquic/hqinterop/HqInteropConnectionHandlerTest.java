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
package org.jquic.hqinterop;

import org.jquic.quic.streamapi.QuicConnectionControl;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;
 
class HqInteropConnectionHandlerTest {
 
    @Test
    void testHandleGetRequest() throws IOException {
        long streamId = 4L; // Client-initiated bidirectional stream
        HqInteropRequestHandler requestHandler = path -> ("Hello from jQuic hq-interop! Path: " + path + "\n").getBytes(StandardCharsets.UTF_8);
        HqInteropConnectionHandler handler = new HqInteropConnectionHandler(requestHandler);
        
        QuicConnectionControl control = mock(QuicConnectionControl.class);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DataOutputStream dataOut = new DataOutputStream(out);
        DataOutputStream spyDataOut = spy(dataOut);
 
        // 1. New stream allocated
        handler.onNewClientStreamAllocated(streamId, control, spyDataOut, QuicConnectionControl.StreamType.Bidirectional);
 
        // 2. Receive request data "GET /index.html\n"
        byte[] request = "GET /index.html\n".getBytes(StandardCharsets.UTF_8);
        handler.onStreamDataReceived(streamId, control, request, true, null);
 
        // 3. Verify response
        String response = out.toString(StandardCharsets.UTF_8);
        assertTrue(response.contains("Hello from jQuic hq-interop!"));
        assertTrue(response.contains("Path: /index.html"));
 
        // 4. Verify stream closed
        verify(spyDataOut).close();
    }
 
    @Test
    void testIncompleteRequest() {
        long streamId = 4L;
        HqInteropRequestHandler requestHandler = path -> ("Path: " + path).getBytes(StandardCharsets.UTF_8);
        HqInteropConnectionHandler handler = new HqInteropConnectionHandler(requestHandler);
        
        QuicConnectionControl control = mock(QuicConnectionControl.class);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DataOutputStream dataOut = new DataOutputStream(out);
 
        handler.onNewClientStreamAllocated(streamId, control, dataOut, QuicConnectionControl.StreamType.Bidirectional);
 
        // Receive part 1
        handler.onStreamDataReceived(streamId, control, "GET /".getBytes(StandardCharsets.UTF_8), false, null);
        assertEquals(0, out.size(), "Should not respond yet");
 
        // Receive part 2
        handler.onStreamDataReceived(streamId, control, "test\n".getBytes(StandardCharsets.UTF_8), true, null);
        
        String response = out.toString(StandardCharsets.UTF_8);
        assertTrue(response.contains("Path: /test"));
    }
}
