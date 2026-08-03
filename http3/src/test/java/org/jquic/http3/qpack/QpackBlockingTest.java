package org.jquic.http3.qpack;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

public class QpackBlockingTest {

    @Test
    public void testStreamBlockingAndUnblocking() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        // maxBlockedStreams = 10
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream(), 4096);
        QpackBlockingManager blockingManager = new QpackBlockingManager(10, (sId, buf) -> {
            try { return decoder.decodeHeaders(sId, buf); } catch (Exception ex) { throw new RuntimeException(ex); }
        });
        decoder.setUnblockedStreamListener(blockingManager::tryUnblockStreams);
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        coupler.bind(encoder, decoder);

        decoder.setDynamicTableCapacity(1024);
        encoder.setDynamicTableCapacity(1024);

        // 1. Prepare a header block that requires an entry not yet in the table
        // Absolute index 0.
        // We manually construct it to ensure it requires RIC=1.
        // RIC=1, Base=1.
        ByteBuffer headerBlock = ByteBuffer.allocate(10);
        headerBlock.put((byte) 0x02); // Encoded RIC=2 (Actual RIC=1)
        headerBlock.put((byte) 0x00); // Base=1 (Sign=0, Delta=0)
        headerBlock.put((byte) 0x80); // Indexed Dynamic, Relative Index 0
        headerBlock.flip();

        AtomicReference<List<Header>> unblockedHeaders = new AtomicReference<>();
        blockingManager.setUnblockedStreamListener(new Decoder.UnblockedStreamListener() {
            @Override
            public void onHeadersDecoded(long streamId, List<Header> headers) {
                unblockedHeaders.set(headers);
            }
            @Override
            public void onDecodingError(long streamId, Exception e) {
                fail("Decoding error: " + e.getMessage());
            }
        });

        // 2. Try to decode. Should throw exception
        assertThrows(QpackRequiredInsertCountException.class, () -> decoder.decodeHeaders(100, headerBlock.duplicate()));
        
        // Manually block it as Http3ConnectionHandler would do
        try {
            decoder.decodeHeaders(100, headerBlock);
        } catch (QpackRequiredInsertCountException e) {
            blockingManager.blockStream(100, e.getFrame(), e.getRequiredInsertCount());
        }

        // 3. Now insert the missing entry into the dynamic table via encoder
        encoder.encodeHeaders(200, List.of(new Header("custom-key", "custom-value")));
        // This should trigger onEncoderData on decoder which calls tryUnblockStreams automatically
        // but since we are not using the listener in manual mode:
        // (Wait, we DID set the listener above)
        // blockingManager.tryUnblockStreams(decoder.getInsertCount()); 

        // 4. Verify unblocked headers
        assertNotNull(unblockedHeaders.get(), "Headers should have been unblocked");
        assertEquals(1, unblockedHeaders.get().size());
        assertEquals("custom-key", unblockedHeaders.get().getFirst().name());
        assertEquals("custom-value", unblockedHeaders.get().getFirst().value());
    }

    @Test
    public void testMaxBlockedStreamsExceeded() throws Exception {
        QpackDecoder decoder = new QpackDecoder(null, 4096);
        QpackBlockingManager blockingManager = new QpackBlockingManager(1, (sId, buf) -> {
            try { return decoder.decodeHeaders(sId, buf); } catch (Exception ex) { throw new RuntimeException(ex); }
        });
        decoder.setDynamicTableCapacity(1024);

        // RIC=1
        ByteBuffer hb1 = ByteBuffer.wrap(new byte[]{0x02, 0x00, (byte)0x80});
        ByteBuffer hb2 = ByteBuffer.wrap(new byte[]{0x02, 0x00, (byte)0x80});

        // First one blocks
        try {
            decoder.decodeHeaders(1, hb1);
        } catch (QpackRequiredInsertCountException e) {
            blockingManager.blockStream(1, e.getFrame(), e.getRequiredInsertCount());
        }

        // Second one should trigger error because maxBlockedStreams = 1
        try {
            decoder.decodeHeaders(2, hb2);
            fail("Should have thrown QpackRequiredInsertCountException");
        } catch (QpackRequiredInsertCountException e) {
            QpackException ex = assertThrows(QpackException.class, () -> blockingManager.blockStream(2, e.getFrame(), e.getRequiredInsertCount()));
            assertEquals(QpackException.QPACK_DECOMPRESSION_FAILED, ex.getErrorCode());
        }
    }
    
    @Test
    public void testMultipleBlockedStreamsUnblockedInOrder() throws Exception {
        QpackTestCoupler coupler = new QpackTestCoupler();
        QpackDecoder decoder = new QpackDecoder(coupler.getDecoderStream(), 4096);
        QpackBlockingManager blockingManager = new QpackBlockingManager(10, (sId, buf) -> {
            try { return decoder.decodeHeaders(sId, buf); } catch (Exception ex) { throw new RuntimeException(ex); }
        });
        decoder.setUnblockedStreamListener(blockingManager::tryUnblockStreams);
        QpackEncoder encoder = new QpackEncoder(coupler.getEncoderStream());
        coupler.bind(encoder, decoder);

        decoder.setDynamicTableCapacity(1024);
        encoder.setDynamicTableCapacity(1024);

        List<Long> decodedOrder = new ArrayList<>();
        blockingManager.setUnblockedStreamListener(new Decoder.UnblockedStreamListener() {
            @Override
            public void onHeadersDecoded(long streamId, List<Header> headers) {
                decodedOrder.add(streamId);
            }
            @Override
            public void onDecodingError(long streamId, Exception e) {}
        });

        // Stream 1 requires RIC 2
        ByteBuffer hb1 = ByteBuffer.wrap(new byte[]{0x03, 0x00, (byte)0x80}); // RIC=2, Base=2, Relative=0 (Abs=1)
        // Stream 2 requires RIC 1
        ByteBuffer hb2 = ByteBuffer.wrap(new byte[]{0x02, 0x00, (byte)0x80}); // RIC=1, Base=1, Relative=0 (Abs=0)

        try { decoder.decodeHeaders(1, hb1); } catch (QpackRequiredInsertCountException e) { blockingManager.blockStream(1, e.getFrame(), e.getRequiredInsertCount()); }
        try { decoder.decodeHeaders(2, hb2); } catch (QpackRequiredInsertCountException e) { blockingManager.blockStream(2, e.getFrame(), e.getRequiredInsertCount()); }

        // Insert first entry (RIC becomes 1)
        encoder.encodeHeaders(10, List.of(new Header("k1", "v1")));
        // This should trigger onEncoderData on decoder which calls tryUnblockStreams automatically
        // blockingManager.tryUnblockStreams(decoder.getInsertCount());
        assertEquals(List.of(2L), decodedOrder, "Stream 2 should be unblocked first");

        // Insert second entry (RIC becomes 2)
        encoder.encodeHeaders(11, List.of(new Header("k2", "v2")));
        // blockingManager.tryUnblockStreams(decoder.getInsertCount());
        assertEquals(List.of(2L, 1L), decodedOrder, "Stream 1 should be unblocked next");
    }
}
