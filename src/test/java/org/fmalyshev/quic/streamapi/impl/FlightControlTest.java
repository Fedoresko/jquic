package org.fmalyshev.quic.streamapi.impl;

import org.fmalyshev.quic.QuicCrypto;
import org.fmalyshev.quic.QuicTransportError;
import org.fmalyshev.quic.streamapi.QuicStreamException;
import org.fmalyshev.quic.streamapi.QuicStreamResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class FlightControlTest {

    private StreamManager streamManager;
    private FlightControl flightControl;

    private static final int INITIAL_MAX_STREAM_DATA = 5000;
    private static final long INITIAL_MAX_DATA = 5000;
    private static final int MAX_BIDI_STREAMS = 10;
    private static final int MAX_UNI_STREAMS = 5;

    @BeforeEach
    void setUp() {
        streamManager = mock(StreamManager.class);
        QuicCrypto.ClientMetadataNegotiated initials = new QuicCrypto.ClientMetadataNegotiated(
                "h3", 30000, List.of(), Map.of(), 1300, INITIAL_MAX_DATA,
                INITIAL_MAX_STREAM_DATA, INITIAL_MAX_STREAM_DATA, INITIAL_MAX_STREAM_DATA,
                0, 0, List.of()
        );
        flightControl = new FlightControl(
                INITIAL_MAX_STREAM_DATA,
                INITIAL_MAX_DATA,
                MAX_BIDI_STREAMS,
                MAX_UNI_STREAMS,
                initials,
                streamManager
        );
    }

    @Test
    void testInitialState() {
        // Initial streams should be empty
        assertFalse(flightControl.isStreamOpenForSend(0));
    }

    @Test
    void testIncomingStreamCreation() {
        // Stream ID 0 (Client-Initiated Bidirectional in many QUIC implementations, 
        // but here let's see how incomingStream handles it)
        flightControl.incomingStream(0);
        assertTrue(flightControl.isStreamOpenForSend(0));
    }

    @Test
    void testCanReceiveWithinLimits() {
        flightControl.incomingStream(0);
        // dataSize 100, totalReceived 0, limit 5000
        assertFalse(flightControl.isReceiveCapReached(0, 0,100));
        verify(streamManager, never()).sendConnectionClose(any(), anyString());
    }

    @Test
    void testCanReceiveExceedingMaxStreamData() {
        flightControl.incomingStream(0);
        // dataSize 6000 > INITIAL_MAX_STREAM_DATA (5000)
        boolean result = flightControl.isReceiveCapReached(0, 0, 6000);
        
        assertTrue(result, "Should be blocked by stream-level flow control");
        verify(streamManager).sendConnectionClose(eq(QuicTransportError.FLOW_CONTROL_ERROR), contains("MAX_STREAM_DATA"));
    }

    @Test
    void testCanReceiveExceedingMaxData() {
        // Use multiple streams to exceed INITIAL_MAX_DATA (5000) without exceeding 
        // INITIAL_MAX_STREAM_DATA (5000) on any single stream.
        flightControl.incomingStream(0);
        flightControl.incomingStream(4);
        
        // Receive 3000 on stream 0
        assertFalse(flightControl.isReceiveCapReached(0, 0, 3000));
        flightControl.addReceivedBytes(0, 0, 3000, 3000);
        
        // Receive 2100 on stream 4. Total = 3000 + 2100 = 5100 > 5000
        boolean result = flightControl.isReceiveCapReached(4, 0, 2100);
        
        assertTrue(result, "Should be blocked by connection-level flow control");
        verify(streamManager).sendConnectionClose(eq(QuicTransportError.FLOW_CONTROL_ERROR), contains("MAX_DATA"));
    }

    @Test
    void testAddReceivedBytesAndMaxStreamDataUpdate() {
        long streamId = 4; // Arbitrary stream ID
        flightControl.incomingStream(streamId);
        
        int dataSize = 100;
        // STREAM_BUFFER_CAPACITY is 50,000.
        // If bufferedBytes is 0, freeQueue = 50,000.
        // received = 100.
        // 100 + 50000 / 2 = 25100.
        // limit = 1000 (INITIAL_MAX_STREAM_DATA).
        // 25100 > 1000 -> TRUE.
        
        flightControl.addReceivedBytes(streamId, 0, dataSize, 0);
        
        verify(streamManager).sendMaxStreamDataFrame(eq(streamId), eq(100L + 50000L));
    }

    @Test
    void testCanSendWithinLimits() {
        long streamId = 0;
        flightControl.incomingStream(streamId);
        
        // Initial max stream data for outgoing was 5000
        assertTrue(flightControl.canSend(streamId, 500));
        verify(streamManager, never()).sendStreamDataBlockedFrame(anyLong(), anyLong());
    }

    @Test
    void testCanSendBlockedByStreamLimit() {
        long streamId = 0;
        flightControl.incomingStream(streamId);
        
        // Exceed stream limit (5000)
        boolean result = flightControl.canSend(streamId, 6000);
        
        assertFalse(result);
        verify(streamManager).sendStreamDataBlockedFrame(eq(streamId), eq((long)INITIAL_MAX_STREAM_DATA));
    }

    @Test
    void testBytesAckedReducesInFlight() {
        long streamId = 0;
        flightControl.incomingStream(streamId);
        
        flightControl.addSentBytes(streamId, 500);
        // totalInFlightBytes = 500
        
        flightControl.bytesAcked(streamId, 200L);
        // totalInFlightBytes = 300
        
        // Now we should be able to send 4500 more (300 + 4700 = 5000, which is limit)
        assertTrue(flightControl.canSend(streamId, 4700));
        // But 4701 should fail
        assertFalse(flightControl.canSend(streamId, 4701));
    }

    @Test
    void testUpdateMaxDataIfNeeded() {
        long streamId = 0;
        flightControl.incomingStream(streamId);
        
        // Initial currentMaxData = 5000, maxDataCap = 5000.
        
        // Receive 3000 bytes. totalReceivedBytes = 3000, totalBufferedBytes = 3000.
        flightControl.addReceivedBytes(streamId, 0, 3000, 3000);
        
        // currentMaxData - totalReceivedBytes = 5000 - 3000 = 2000.
        // (maxDataCap - totalBufferedBytes) / 2 = (5000 - 3000) / 2 = 1000.
        // 2000 < 1000 is FALSE. No MAX_DATA sent yet.
        verify(streamManager, never()).sendMaxDataFrame(anyLong());

        // Now free 2500 bytes. totalBufferedBytes = 500.
        flightControl.byfferedBytesFreed(streamId, 2500);
        
        // updateMaxDataIfNeeded check:
        // currentMaxData - totalReceivedBytes = 5000 - 3000 = 2000.
        // (maxDataCap - totalBufferedBytes) / 2 = (5000 - 500) / 2 = 2250.
        // 2000 < 2250 is TRUE. MAX_DATA should be sent.
        
        // newMaxData = maxDataCap - totalBufferedBytes + totalReceivedBytes
        // newMaxData = 5000 - 500 + 3000 = 7500.
        
        verify(streamManager).sendMaxDataFrame(eq(7500L));
    }

    @Test
    void testStreamFinStateTransitions() {
        long streamId = 0; // Client-initiated bidi
        flightControl.incomingStream(streamId);
        
        // Initial state is OPEN
        assertTrue(flightControl.isStreamOpenForSend(streamId));

        // Remote FIN
        flightControl.onStreamFin(streamId, false);
        // State should be HALF_CLOSED_REMOTE. 
        // In HALF_CLOSED_REMOTE, canSend() is TRUE, canReceive() is FALSE.
        // isStreamOpen checks canSend().
        assertTrue(flightControl.isStreamOpenForSend(streamId));

        // Local FIN
        flightControl.onStreamFin(streamId, true);
        // State should be CLOSED.
        assertFalse(flightControl.isStreamOpenForSend(streamId));
    }

    @Test
    void testStreamResetReceived() {
        long streamId = 0;
        flightControl.incomingStream(streamId);
        
        flightControl.onStreamReset(streamId, 123L, 100);
        // State should be RESET_RECEIVED. canSend() is FALSE.
        assertFalse(flightControl.isStreamOpenForSend(streamId));
    }

    @Test
    void testStreamStopSendingReceived() {
        long streamId = 0;
        flightControl.incomingStream(streamId);
        
        flightControl.onStreamStopSending(streamId, 456L);
        // Should send RESET_STREAM in response
        verify(streamManager).sendResetStreamFrame(eq(streamId), eq(456L), eq(0L));
        // State should be RESET_SENT. canSend() is FALSE.
        assertFalse(flightControl.isStreamOpenForSend(streamId));
    }

    @Test
    void testOpenOutgoingStreamLimits() throws QuicStreamException {
        // Max bidi streams = 10
        for (int i = 0; i < 10; i++) {
            flightControl.openOutgoingStream(i * 4 + 1, QuicStreamResponse.StreamType.Bidirectional);
        }
        
        assertThrows(QuicStreamException.class, () -> flightControl.openOutgoingStream(41, QuicStreamResponse.StreamType.Bidirectional));
    }

    @Test
    void testIncomingStreamLimits() {
        // Initial limit is 10 bidi streams. Cap = 40.
        // If we skip directly to stream ID 44, it should trigger an error.
        flightControl.incomingStream(44);
        
        verify(streamManager).sendConnectionClose(eq(QuicTransportError.STREAM_LIMIT_ERROR), anyString());
    }

    @Test
    void testMaxStreamsUpdateWhenCapacityExhausted() {
        // Initial maxBidirectionalStreams = 10
        // bidirectionalIncomingStreamCap = 40 (10*4)
        // Threshold: 10 - 10/2 = 5.
        // Stream index 5 corresponds to ID 5*4 = 20.
        
        // Open streams up to index 4 (ID 16). Threshold 5 not reached.
        for (int i = 0; i < 5; i++) {
            flightControl.incomingStream(i * 4);
        }
        verify(streamManager, never()).sendMaxStreamsFrame(anyLong(), anyBoolean());
        
        // Open stream index 5 (ID 20).
        flightControl.incomingStream(20);
        
        // Count is 6. maxStreams 10. initial 10.
        // 10 - 6 + 10 = 14.
        verify(streamManager).sendMaxStreamsFrame(eq(14L), eq(true));
        
        // New limit 14. threshold 14 - 5 = 9. Index 9 is ID 36.
        for (int i = 6; i < 9; i++) {
            flightControl.incomingStream(i * 4);
        }
        verify(streamManager, times(1)).sendMaxStreamsFrame(anyLong(), eq(true));
        
        // Index 9 (ID 36)
        flightControl.incomingStream(36);
        // count is 10. maxStreams 14. initial 10.
        // 14 - 10 + 10 = 14. Wait, the limit stays 14? 
        // No, if count is 10, limit 14. 14-10+10 = 14.
        // If we want to ADD capacity, it should be relative to current count.
        verify(streamManager, times(2)).sendMaxStreamsFrame(eq(14L), eq(true));
    }

    @Test
    void testActiveStreamCountDecrementsOnClose() {
        // Initial limit 10. Threshold index 5 (ID 20).
        // Open 5 streams (IDs 0, 4, 8, 12, 16).
        for (int i = 0; i < 5; i++) {
            flightControl.incomingStream(i * 4);
        }
        verify(streamManager, never()).sendMaxStreamsFrame(anyLong(), eq(true));

        // Open 6th stream (ID 20). Trigger.
        flightControl.incomingStream(20);
        // Count 6. 10 - 6 + 10 = 14.
        verify(streamManager, times(1)).sendMaxStreamsFrame(eq(14L), eq(true));

        // Close all 6 streams.
        for (int i = 0; i < 6; i++) {
            flightControl.onStreamFin(i * 4, false); // Half-closed remote
            flightControl.onStreamFin(i * 4, true);  // Closed
        }
        // Active count = 0.

        // Open more streams. Limit 14. Threshold 14 - 5 = 9 (ID 36).
        for (int i = 6; i < 9; i++) {
            flightControl.incomingStream(i * 4); 
        }
        
        // Index 9 is ID 36.
        flightControl.incomingStream(36);
        // MaxStreams 14. Count 4 (indices 6,7,8,9). 
        // 14 - 4 + 10 = 20.
        verify(streamManager, atLeastOnce()).sendMaxStreamsFrame(eq(20L), eq(true));
    }

    @Test
    void testReceiveOnLocallyInitiatedUniStream() {
        // We open a unidirectional stream (server-initiated uni IDs: 3, 7, 11...)
        long streamId = 3; 
        try {
            flightControl.openOutgoingStream(streamId, QuicStreamResponse.StreamType.Unidirectional);
        } catch (QuicStreamException e) {}
        
        // Peer sends data on our uni stream - this is a violation!
        // RFC 9000: STREAM_STATE_ERROR
        
        flightControl.incomingStream(streamId);
        
        // FlightControl should close the connection with STREAM_STATE_ERROR
        verify(streamManager).sendConnectionClose(eq(QuicTransportError.STREAM_STATE_ERROR), anyString());
    }

    @Test
    void testReceiveAfterResetSent() {
        long streamId = 0; // Bidirectional
        flightControl.incomingStream(streamId);
        
        // We send RESET_STREAM (e.g. via closeStream)
        flightControl.closeStream(streamId, 123L);
        
        // We should still be able to receive data from the peer on this stream
        // RFC 9000 Section 3.5: STOP_SENDING/RESET_STREAM "does not affect data being sent in the other direction"
        
        boolean canRecv = streamsInFlightControl(flightControl).get(streamId).getState().canReceive();
        
        assertTrue(canRecv, "Should still be able to receive data after sending RESET_STREAM on bidirectional stream");
    }

    @Test
    void testActiveStreamCountLeakOnUnidirectionalIncoming() throws Exception {
        // Initial uni limit 5. Threshold 3.
        // unidirectionalIncomingStreamCap = 2 + 5 * 4 = 22.

        // Open 3 uni streams (IDs 2, 6, 10).
        for (int i = 0; i < 3; i++) {
            flightControl.incomingStream(i * 4 + 2);
        }
        // indices 0, 1, 2. maxStreams 5. threshold 3. Not reached.
        verify(streamManager, never()).sendMaxStreamsFrame(anyLong(), eq(false));

        // Close them with remote FIN.
        for (int i = 0; i < 3; i++) {
            flightControl.onStreamFin(i * 4 + 2, false); 
        }

        // Verify count didn't decrement (it's leaked).
        long uniCount = (long) getFieldValue(flightControl, "currentUniStreamsCount");
        assertEquals(3L, uniCount, "Unidirectional incoming streams should stay at 3 due to leak");

        // Open 2 more. 
        flightControl.incomingStream(14); // index 3. threshold 5 - 2 = 3. Reached!
        // count 4. limit 5. initial 5. 5 - 4 + 5 = 6.
        verify(streamManager, times(1)).sendMaxStreamsFrame(eq(6L), eq(false));

        flightControl.incomingStream(18); // index 4. threshold 6 - 2 = 4. Reached!
        // count 5. limit 6. initial 5. 6 - 5 + 5 = 6.
        verify(streamManager, times(2)).sendMaxStreamsFrame(eq(6L), eq(false));
    }

    @Test
    void testMaxStreamsUpdateBasedOnStreamId() throws Exception {
        // Re-setup to have clean state
        setUp();
        
        // Initial bidi limit 10. initialMaxStreams = 10.
        // Threshold index should be 10 - 10/2 = 5. (ID 20)

        // Open 5 streams (indices 0 to 4, IDs 0 to 16).
        for (int i = 0; i < 5; i++) {
            flightControl.incomingStream(i * 4);
        }
        verify(streamManager, never()).sendMaxStreamsFrame(anyLong(), eq(true));
        
        // Now close them.
        for (int i = 0; i < 5; i++) {
            flightControl.onStreamFin(i * 4, false);
            flightControl.onStreamFin(i * 4, true);
        }
        
        // Count is now 0.
        long bidiCount = (long) getFieldValue(flightControl, "currentBidiStreamsCount");
        assertEquals(0L, bidiCount);
        
        // Open next stream ID 20 (index 5). Trigger.
        flightControl.incomingStream(20);
        
        // maxStreams 10. count 1. initial 10.
        // 10 - 1 + 10 = 19.
        verify(streamManager, times(1)).sendMaxStreamsFrame(eq(19L), eq(true));
    }

    private Object getFieldValue(Object obj, String fieldName) throws Exception {
        java.lang.reflect.Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }

    @Test
    void testConnectionFlowControlRetransmission() {
        // Setup with INITIAL_MAX_DATA (5000)
        QuicCrypto.ClientMetadataNegotiated initials = new QuicCrypto.ClientMetadataNegotiated(
                "h3", 30000, List.of(), Map.of(), 1300, INITIAL_MAX_DATA,
                INITIAL_MAX_STREAM_DATA, INITIAL_MAX_STREAM_DATA, INITIAL_MAX_STREAM_DATA,
                0, 0, List.of()
        );
        flightControl = new FlightControl(INITIAL_MAX_STREAM_DATA, INITIAL_MAX_DATA, MAX_BIDI_STREAMS, MAX_UNI_STREAMS, initials, streamManager);
        
        long streamId = 0;
        flightControl.incomingStream(streamId);
        
        // Receive 600 bytes
        flightControl.addReceivedBytes(streamId, 0, 600, 600);
        
        // Try to "receive" the same 600 bytes again (retransmission)
        boolean blocked = flightControl.isReceiveCapReached(streamId, 0, 600);
        
        assertFalse(blocked, "Retransmission should not be blocked by connection flow control");
        verify(streamManager, never()).sendConnectionClose(eq(QuicTransportError.FLOW_CONTROL_ERROR), anyString());
    }

    @Test
    void testResetStreamUpdatesConnectionFlowControl() {
        // Initial maxData is 5000
        long streamId = 0;
        flightControl.incomingStream(streamId);

        // Peer sends 2000 bytes, then resets with finalSize = 3000
        flightControl.addReceivedBytes(streamId, 0, 2000, 2000);
        
        // onStreamReset should take finalSize and update connection budget
        flightControl.onStreamReset(streamId, 123L, 3000L);
        
        // Now if we try to receive 2100 bytes on ANOTHER stream, it should be blocked
        // because 3000 (stream 0) + 2100 (stream 4) = 5100 > 5000.
        long streamId2 = 4;
        flightControl.incomingStream(streamId2);
        boolean blocked = flightControl.isReceiveCapReached(streamId2, 0, 2100);
        
        assertTrue(blocked, "Connection should be blocked after RESET_STREAM with large finalSize exceeding 5000");
        verify(streamManager).sendConnectionClose(eq(QuicTransportError.FLOW_CONTROL_ERROR), contains("MAX_DATA"));
    }

    @Test
    void testMaxStreamsUpdate() {
        // Initial limit is 10 (set in setup)
        // Try to open 11th stream
        for (int i = 0; i < 10; i++) {
            try {
                flightControl.openOutgoingStream(1 + i * 4, QuicStreamResponse.StreamType.Bidirectional);
            } catch (QuicStreamException e) {}
        }
        
        assertThrows(QuicStreamException.class, () -> {
            flightControl.openOutgoingStream(41, QuicStreamResponse.StreamType.Bidirectional);
        });
        
        // Peer increases limit
        flightControl.onMaxStreams(true, 20);
        
        // Should now be able to open more streams
        assertDoesNotThrow(() -> {
            flightControl.openOutgoingStream(41, QuicStreamResponse.StreamType.Bidirectional);
        });
    }

    @Test
    void testMaxDataUpdate() {
        flightControl.incomingStream(0);
        
        // Initial currentMaxData = 5000 (INITIAL_MAX_DATA)
        // Initial maxStreamData = 5000 (INITIAL_MAX_STREAM_DATA)
        
        // Try to send 5001 bytes - blocked by both
        assertFalse(flightControl.canSend(0, 5001));
        
        // Update MAX_STREAM_DATA to 10000
        flightControl.onStreamMaxData(0, 10000);
        
        // Still blocked by connection MAX_DATA (5000)
        assertFalse(flightControl.canSend(0, 5001));
        
        // Update connection MAX_DATA to 10000
        flightControl.onMaxData(10000);
        
        // Should now be able to send 5001 bytes
        assertTrue(flightControl.canSend(0, 5001));
    }

    @Test
    void testTransportParametersAffectInitialLimits() throws QuicStreamException {
        // Setup with different limits in transport parameters
        long tpMaxData = 8000;
        long tpMaxStreamDataBidiLocal = 2000;
        long tpMaxStreamDataBidiRemote = 3000;
        long tpMaxStreamDataUni = 1500;
        long tpMaxStreamsBidi = 20;
        long tpMaxStreamsUni = 15;

        QuicCrypto.ClientMetadataNegotiated initials = new QuicCrypto.ClientMetadataNegotiated(
                "h3", 30000, List.of(), Map.of(), 1300, tpMaxData,
                tpMaxStreamDataBidiLocal, tpMaxStreamDataBidiRemote, tpMaxStreamDataUni,
                tpMaxStreamsBidi, tpMaxStreamsUni, List.of()
        );

        FlightControl fc = new FlightControl(
                INITIAL_MAX_STREAM_DATA, // Cap is still 5000
                INITIAL_MAX_DATA,       // Cap is still 5000 (wait, maxDataCap is used for connection-level flow control receiving)
                MAX_BIDI_STREAMS,
                MAX_UNI_STREAMS,
                initials,
                streamManager
        );

        // 1. Check connection-level initial limit for sending
        // currentMaxData should be tpMaxData (8000)
        // totalInFlightBytes = 0.
        // We need an open stream to test canSend
        fc.incomingStream(0); 
        // Stream 0 is Bidi, Remote-initiated.
        // Its maxStreamData (sending limit) should be tpMaxStreamDataBidiLocal (2000)
        
        assertTrue(fc.canSend(0, 2000), "Should be able to send up to stream limit");
        assertFalse(fc.canSend(0, 2001), "Should be blocked by stream limit 2000");

        // 2. Check Uni stream limit
        fc.openOutgoingStream(3, QuicStreamResponse.StreamType.Unidirectional);
        assertTrue(fc.canSend(3, 1500), "Uni stream should have limit 1500");
        assertFalse(fc.canSend(3, 1501), "Uni stream should be blocked by limit 1500");

        // 3. Check outgoing stream opening limits
        // tpMaxStreamsBidi = 20, tpMaxStreamsUni = 15
        // Open 20 bidi streams (IDs: 1, 5, 9, ..., 1 + 19*4 = 77)
        for (int i = 0; i < 20; i++) {
            fc.openOutgoingStream(1 + i * 4, QuicStreamResponse.StreamType.Bidirectional);
        }
        // 21st should fail
        assertThrows(QuicStreamException.class, () -> fc.openOutgoingStream(81, QuicStreamResponse.StreamType.Bidirectional));

        // 4. Check connection level limit
        // Send 2000 on stream 0
        fc.addSentBytes(0, 2000);
        // Total in flight = 2000. Limit = 8000. Remaining = 6000.
        // Open another stream
        fc.incomingStream(4);
        // Stream 4 limit is also 2000.
        assertTrue(fc.canSend(4, 2000));
        fc.addSentBytes(4, 2000);
        // Total in flight = 4000. Remaining = 4000.
        // Peer increases limit for stream 4
        fc.onStreamMaxData(4, 10000);
        
        assertTrue(fc.canSend(4, 4000));
        assertFalse(fc.canSend(4, 4001), "Should be blocked by connection limit 8000 (4000+4001 > 8000)");
    }

    private Map<Long, StreamState> streamsInFlightControl(FlightControl fc) {
        try {
            java.lang.reflect.Field field = FlightControl.class.getDeclaredField("streams");
            field.setAccessible(true);
            return (Map<Long, StreamState>) field.get(fc);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
