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
package org.jquic.http3;

import org.jquic.quic.streamapi.QuicConnectionControl;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class Http3HeaderLimitTest {

    @Test
    public void testRemoteHeaderLimitExceeded() throws Exception {
        Http3RequestHandler handler = mock(Http3RequestHandler.class);
        Http3ConnectionHandler connectionHandler = new Http3ConnectionHandler(1, handler);
        QuicConnectionControl control = mock(QuicConnectionControl.class);
        
        // Setup mandatory streams
        connectionHandler.onConnectionEstablished(control);
        
        // Setup Decoder and Encoder streams
        ByteArrayOutputStream decoderOut = new ByteArrayOutputStream();
        connectionHandler.onNewServerStreamAllocated(3, new DataOutputStream(decoderOut), QuicConnectionControl.StreamType.Unidirectional);
        
        ByteArrayOutputStream encoderOut = new ByteArrayOutputStream();
        connectionHandler.onNewServerStreamAllocated(7, new DataOutputStream(encoderOut), QuicConnectionControl.StreamType.Unidirectional);
        
        // Receive SETTINGS to set local limits (already set by default but let's be explicit)
        // Default localMaxFieldSectionSize is 128KB. Let's set it smaller via internal field if possible or just use a large frame.
        // Actually Http3ConnectionHandler.DEFAULT_MAX_FIELD_SECTION_SIZE = 128 * 1024L;
        
        // Create a request stream
        long requestStreamId = 0; // Client-initiated bidirectional
        ByteArrayOutputStream requestOut = new ByteArrayOutputStream();
        connectionHandler.onNewClientStreamAllocated(requestStreamId, control, new DataOutputStream(requestOut), QuicConnectionControl.StreamType.Bidirectional, false);
        
        // Construct a HEADERS frame that is larger than the default limit (128KB + 1)
        int size = 128 * 1024 + 1;
        byte[] largeHeadersPayload = new byte[size];
        
        // Frame Type: HEADERS (0x01)
        ByteBuffer frameHeader = ByteBuffer.allocate(10);
        // QuicVarint 0x01
        frameHeader.put((byte) 0x01);
        // QuicVarint size
        // 128KB+1 = 131073. Varint for 131073:
        // 131073 = 0x20001
        // In QuicVarint (8 bytes if > 2^30, 4 bytes if > 2^14, 2 bytes if > 2^6)
        // 131073 > 16383 (2^14-1), so 4 bytes.
        // 0x80 | 0x02, 0x00, 0x01
        frameHeader.put((byte) 0x80);
        frameHeader.put((byte) 0x02);
        frameHeader.put((byte) 0x00);
        frameHeader.put((byte) 0x01);
        frameHeader.flip();
        
        byte[] frameBytes = new byte[frameHeader.remaining()];
        frameHeader.get(frameBytes);
        
        connectionHandler.onStreamDataReceived(requestStreamId, control, frameBytes, false, null, false);
        connectionHandler.onStreamDataReceived(requestStreamId, control, largeHeadersPayload, false, null, false);
        
        // Verify that the stream was closed with H3_REQUEST_CANCELLED
        verify(control).closeStream(eq(requestStreamId), eq((long)Http3Server.H3_REQUEST_CANCELLED));
    }
}
