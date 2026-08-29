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

import org.jquic.quic.QuicVarint;
import org.jquic.quic.streamapi.QuicConnectionControl;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

public class Http3GoAwayTest {

    @Test
    public void testGoAwayStateTransition() throws Exception {
        Http3RequestHandler handler = mock(Http3RequestHandler.class);
        Http3ConnectionHandler connectionHandler = new Http3ConnectionHandler(1, handler);
        QuicConnectionControl control = mock(QuicConnectionControl.class);

        // Setup mandatory streams
        connectionHandler.onConnectionEstablished(control);

        // Identify the control stream
        // Client-initiated unidirectional stream ID: least significant bit is 0 (client), second bit is 1 (unidirectional)
        // 0x02, 0x06, 0x0A, 0x0E...
        long clientControlStreamId = 2;

        // Initialize client control stream
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        connectionHandler.onNewClientStreamAllocated(clientControlStreamId, control, new DataOutputStream(out), QuicConnectionControl.StreamType.Unidirectional, false);

        // Send stream type 0x00 (Control Stream)
        connectionHandler.onStreamDataReceived(clientControlStreamId, control, new byte[]{0x00}, false, null, false);

        // Send SETTINGS frame (mandatory first frame)
        ByteArrayOutputStream settingsPayloadStream = new ByteArrayOutputStream();
        DataOutputStream settingsDataOut = new DataOutputStream(settingsPayloadStream);
        QuicVarint.write(settingsDataOut, 0x06); // MAX_FIELD_SECTION_SIZE
        QuicVarint.write(settingsDataOut, 1024);
        byte[] settingsFrame = createFrame(0x04, settingsPayloadStream.toByteArray());
        connectionHandler.onStreamDataReceived(clientControlStreamId, control, settingsFrame, false, null, false);

        // Send GOAWAY frame (type 0x07) with max stream ID 0
        ByteArrayOutputStream goawayPayloadStream = new ByteArrayOutputStream();
        DataOutputStream goawayDataOut = new DataOutputStream(goawayPayloadStream);
        QuicVarint.write(goawayDataOut, 0);
        byte[] goawayFrame = createFrame(0x07, goawayPayloadStream.toByteArray());

        connectionHandler.onStreamDataReceived(clientControlStreamId, control, goawayFrame, false, null, false);

        // Use reflection to verify state transition
        java.lang.reflect.Field field = connectionHandler.getClass().getDeclaredField("connectionState");
        field.setAccessible(true);
        Object state = field.get(connectionHandler);
        assertEquals("CLOSING", state.toString());

        // Verify that server-initiated stream allocation throws IllegalStateException
        assertThrows(IllegalStateException.class, () -> connectionHandler.openServerStream(QuicConnectionControl.StreamType.Unidirectional));
    }

    @Test
    public void testGoAwayFragmented() throws Exception {
        Http3RequestHandler handler = mock(Http3RequestHandler.class);
        Http3ConnectionHandler connectionHandler = new Http3ConnectionHandler(1, handler);
        QuicConnectionControl control = mock(QuicConnectionControl.class);

        connectionHandler.onConnectionEstablished(control);

        long clientControlStreamId = 2;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        connectionHandler.onNewClientStreamAllocated(clientControlStreamId, control, new DataOutputStream(out), QuicConnectionControl.StreamType.Unidirectional, false);

        // Send stream type 0x00 (Control Stream)
        connectionHandler.onStreamDataReceived(clientControlStreamId, control, new byte[]{0x00}, false, null, false);

        // Send SETTINGS frame in fragments
        ByteArrayOutputStream settingsPayloadStream = new ByteArrayOutputStream();
        DataOutputStream settingsDataOut = new DataOutputStream(settingsPayloadStream);
        QuicVarint.write(settingsDataOut, 0x06);
        QuicVarint.write(settingsDataOut, 1024);
        byte[] settingsFrame = createFrame(0x04, settingsPayloadStream.toByteArray());

        // Fragment 1: only type varint (assume it fits in 1 byte for 0x04)
        connectionHandler.onStreamDataReceived(clientControlStreamId, control, new byte[]{settingsFrame[0]}, false, null, false);
        // Fragment 2: only length varint (assume it fits in 1 byte)
        connectionHandler.onStreamDataReceived(clientControlStreamId, control, new byte[]{settingsFrame[1]}, false, null, false);
        // Fragment 3: payload
        byte[] payload = new byte[settingsFrame.length - 2];
        System.arraycopy(settingsFrame, 2, payload, 0, payload.length);
        connectionHandler.onStreamDataReceived(clientControlStreamId, control, payload, false, null, false);

        // Send GOAWAY frame (type 0x07) in fragments
        ByteArrayOutputStream goawayPayloadStream = new ByteArrayOutputStream();
        DataOutputStream goawayDataOut = new DataOutputStream(goawayPayloadStream);
        QuicVarint.write(goawayDataOut, 0);
        byte[] goawayFrame = createFrame(0x07, goawayPayloadStream.toByteArray());

        // Send type (0x07)
        connectionHandler.onStreamDataReceived(clientControlStreamId, control, new byte[]{goawayFrame[0]}, false, null, false);
        // Send length (0x01)
        connectionHandler.onStreamDataReceived(clientControlStreamId, control, new byte[]{goawayFrame[1]}, false, null, false);
        // Send payload (0x00)
        connectionHandler.onStreamDataReceived(clientControlStreamId, control, new byte[]{goawayFrame[2]}, false, null, false);

        // Verify state transition
        java.lang.reflect.Field field = connectionHandler.getClass().getDeclaredField("connectionState");
        field.setAccessible(true);
        Object state = field.get(connectionHandler);
        assertEquals("CLOSING", state.toString());
    }

    private byte[] createFrame(int type, byte[] payload) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DataOutputStream dataOut = new DataOutputStream(out);
        QuicVarint.write(dataOut, type);
        QuicVarint.write(dataOut, payload.length);
        dataOut.write(payload);
        return out.toByteArray();
    }
}
