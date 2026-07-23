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
package org.jquic.quic;

import org.jquic.quic.buffers.BorrowedPoolBuffer;
import org.jquic.quic.buffers.BufferPool;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.buffers.RootPoolBuffer;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link CryptoFrameRebuilder}.
 *
 * <p>CRYPTO frames carry TLS handshake bytes and are governed by RFC 9001 В§4 and the
 * reliable, ordered byte-stream semantics of RFC 9000 В§19.6.  Key properties under
 * test:
 * <ul>
 *   <li>Fragments may arrive in any order (RFC 9000 В§2.2 stream-like delivery).</li>
 *   <li>Overlapping or retransmitted fragments MUST be tolerated; duplicate data that
 *       is already received MUST be silently ignored (RFC 9000 В§2.2).</li>
 *   <li>The stream is not consumable until every byte from 0 to {@code expectedLength}
 *       has been received contiguously (RFC 9001 В§4.1.3 вЂ” TLS must receive a
 *       complete record before it can process it).</li>
 *   <li>{@code peekEarlyHead} allows reading the beginning of the stream (e.g. TLS
 *       record header) before the full frame length is known, matching the common
 *       pattern of parsing {@code expectedLength} from the first bytes.</li>
 * </ul>
 */
class CryptoFrameRebuilderTest {

    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    // Helpers
    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /** Wrap a plain byte array in a ByteBuffer positioned at 0. */
    private static PoolBuffer buf(byte... bytes) {
        return new RootPoolBuffer(ByteBuffer.wrap(bytes), mock(BufferPool.class), true);
    }

    /** Create a sequential payload of {@code length} bytes starting at {@code start}. */
    private static byte[] sequential(int start, int length) {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) {
            b[i] = (byte) (start + i);
        }
        return b;
    }

    /** Read all remaining bytes from a ByteBuffer without consuming it permanently. */
    private static byte[] drain(ByteBuffer bb) {
        ByteBuffer dup = bb.duplicate();
        byte[] out = new byte[dup.remaining()];
        dup.get(out);
        return out;
    }

    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    // Basic single-fragment delivery
    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /**
     * RFC 9001 В§4.1.3 вЂ“ simplest case: the entire CRYPTO payload arrives in one
     * fragment. After setExpectedLength and addPart the frame must be immediately
     * complete and rebuild() must return the exact bytes.
     */
    @Test
    void singleFragment_completeFrameInOneShot() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        byte[] payload = sequential(0, 10);

        rebuilder.setExpectedLength(10);
        boolean complete = rebuilder.addPart(0, 10, buf(payload));

        assertTrue(complete, "Frame should be complete after the only fragment");
        assertTrue(rebuilder.isComplete());

        ByteBuffer result = rebuilder.rebuild();
        assertArrayEquals(payload, drain(result));
    }

    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    // setExpectedLength called AFTER fragments arrive
    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /**
     * RFC 9001 В§4.1.3 вЂ“ a receiver may buffer fragments before it has parsed the
     * TLS record length.  When setExpectedLength is finally called with the correct
     * value, isComplete must reflect the already-received data.
     */
    @Test
    void setExpectedLength_afterFragmentsArrived_completesImmediately() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        byte[] payload = sequential(0, 8);

        // Fragment arrives before expectedLength is known
        boolean c1 = rebuilder.addPart(0, 8, buf(payload));
        assertFalse(c1, "Cannot be complete: expectedLength not set yet");

        rebuilder.setExpectedLength(8);
        assertTrue(rebuilder.isComplete(), "Already have all bytes; should be complete");

        ByteBuffer result = rebuilder.rebuild();
        assertArrayEquals(payload, drain(result));
    }

    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    // In-order fragmented delivery (RFC 9000 В§2.2)
    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /**
     * CRYPTO stream split across three in-order fragments.  Only the last addPart
     * call should return true.
     */
    @Test
    void threeFragments_inOrder_completesOnLast() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        rebuilder.setExpectedLength(12);

        byte[] p1 = sequential(0, 4);
        byte[] p2 = sequential(4, 4);
        byte[] p3 = sequential(8, 4);

        assertFalse(rebuilder.addPart(0, 4, buf(p1)));
        assertFalse(rebuilder.addPart(4, 4, buf(p2)));
        assertTrue(rebuilder.addPart(8, 4, buf(p3)), "Third fragment completes the frame");

        byte[] expected = sequential(0, 12);
        assertArrayEquals(expected, drain(rebuilder.rebuild()));
    }

    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    // Out-of-order delivery (RFC 9000 В§2.2)
    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /**
     * RFC 9000 В§2.2 вЂ“ stream data may arrive out of order.  The CRYPTO receiver MUST
     * buffer out-of-order data and deliver it in order to TLS.  Here the last fragment
     * arrives first.
     */
    @Test
    void outOfOrder_tailFirst_completesWhenGapFilled() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        rebuilder.setExpectedLength(9);

        byte[] tail   = sequential(6, 3);
        byte[] middle = sequential(3, 3);
        byte[] head   = sequential(0, 3);

        assertFalse(rebuilder.addPart(6, 3, buf(tail)),   "Not complete: missing head and middle");
        assertFalse(rebuilder.addPart(3, 3, buf(middle)), "Not complete: still missing head");
        assertTrue(rebuilder.addPart(0, 3, buf(head)),    "Head fills the final gap; frame complete");

        byte[] expected = sequential(0, 9);
        assertArrayEquals(expected, drain(rebuilder.rebuild()));
    }

    /**
     * Middle fragment arrives last, bridging two previously buffered edges.
     */
    @Test
    void outOfOrder_middleLast_completes() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        rebuilder.setExpectedLength(9);

        assertFalse(rebuilder.addPart(0, 3, buf(sequential(0, 3))));
        assertFalse(rebuilder.addPart(6, 3, buf(sequential(6, 3))));
        assertTrue(rebuilder.addPart(3, 3, buf(sequential(3, 3))), "Middle fills the gap");

        assertArrayEquals(sequential(0, 9), drain(rebuilder.rebuild()));
    }

    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    // Duplicate / overlapping segments (RFC 9000 В§2.2)
    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /**
     * RFC 9000 В§2.2 вЂ“ an endpoint may receive the same stream data multiple times
     * (e.g. due to retransmission).  Duplicate data MUST be silently discarded;
     * only novel bytes fill gaps.
     */
    @Test
    void duplicateFragment_ignoredGracefully() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        rebuilder.setExpectedLength(6);

        byte[] first = sequential(0, 6);
        assertTrue(rebuilder.addPart(0, 6, buf(first)), "Full frame in first call");

        // Exact retransmission вЂ” must not throw and must still be complete
        assertDoesNotThrow(() -> rebuilder.addPart(0, 6, buf(first)));
        assertTrue(rebuilder.isComplete());
    }

    /**
     * Overlapping retransmission: new fragment partially overlaps already-received data.
     * The overlapping portion must be silently ignored; novel bytes fill the gap.
     */
    @Test
    void overlappingFragment_onlyNovelBytesAccepted() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        rebuilder.setExpectedLength(10);

        // Bytes 0вЂ“4 arrive first
        assertFalse(rebuilder.addPart(0, 5, buf(sequential(0, 5))));

        // Retransmission covers bytes 3вЂ“9 (overlap at 3-4, novel at 5-9)
        assertTrue(rebuilder.addPart(3, 7, buf(sequential(3, 7))));

        assertArrayEquals(sequential(0, 10), drain(rebuilder.rebuild()));
    }

    /**
     * A fragment that is entirely within an already-received range must be a no-op.
     */
    @Test
    void fullyContainedDuplicate_isNoOp() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        rebuilder.setExpectedLength(10);

        rebuilder.addPart(0, 10, buf(sequential(0, 10)));

        // Sub-range duplicate
        assertDoesNotThrow(() -> rebuilder.addPart(2, 4, buf(sequential(2, 4))));
        assertTrue(rebuilder.isComplete());
        assertArrayEquals(sequential(0, 10), drain(rebuilder.rebuild()));
    }

    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    // peekEarlyHead вЂ” parsing length from the first bytes
    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /**
     * RFC 9001 В§4.1.3 pattern: the implementation needs the first N bytes of the TLS
     * record to determine the total length before all data has arrived.
     * peekEarlyHead must return exactly the buffered prefix.
     */
    @Test
    void peekEarlyHead_returnsBufferedPrefix() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        byte[] head = {0x01, 0x02, 0x03, 0x04};

        // Add first 4 bytes at offset 0 (simulating header arrival)
        rebuilder.addPart(0, 4, buf(head));

        ByteBuffer peeked = rebuilder.peekEarlyHead(4);
        assertEquals(4, peeked.remaining());
        assertArrayEquals(head, drain(peeked));
    }

    /**
     * peekEarlyHead must return only available contiguous bytes вЂ” not more вЂ” when
     * fewer bytes than requested have arrived.
     */
    @Test
    void peekEarlyHead_fewerBytesThanRequested_returnsAvailable() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        byte[] partial = {0x10, 0x20};

        rebuilder.addPart(0, 2, buf(partial));

        // Ask for 8 bytes, only 2 are available
        ByteBuffer peeked = rebuilder.peekEarlyHead(8);
        assertEquals(2, peeked.remaining(), "Should return only the 2 available bytes");
        assertArrayEquals(partial, drain(peeked));
    }

    /**
     * peekEarlyHead must not cross a gap: if bytes 0-1 are known but byte 2 is
     * missing, asking for 4 bytes should return only 2.
     */
    @Test
    void peekEarlyHead_stopsAtGap() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();

        // Bytes 0-1
        rebuilder.addPart(0, 2, buf(new byte[]{0x01, 0x02}));
        // Gap at byte 2
        // Bytes 3-5
        rebuilder.addPart(3, 3, buf(new byte[]{0x03, 0x04, 0x05}));

        ByteBuffer peeked = rebuilder.peekEarlyHead(6);
        assertEquals(2, peeked.remaining(), "Should stop at gap after byte index 2");
    }

    /**
     * Typical usage pattern: use peekEarlyHead to read a 2-byte length prefix,
     * call setExpectedLength, then deliver remaining fragments to complete the frame.
     */
    @Test
    void peekEarlyHead_thenSetExpectedLength_typicalUsage() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();

        // Simulated TLS record: first 2 bytes are a big-endian length field
        int totalLength = 20;
        byte[] headerBytes = {0x00, (byte) totalLength};
        rebuilder.addPart(0, 2, buf(headerBytes));

        // Parse length from header
        ByteBuffer peeked = rebuilder.peekEarlyHead(2);
        int parsedLength = ((peeked.get() & 0xFF) << 8) | (peeked.get() & 0xFF);
        assertEquals(totalLength, parsedLength);

        rebuilder.setExpectedLength(parsedLength);

        // Deliver the rest of the frame
        byte[] rest = sequential(2, totalLength - 2);
        assertTrue(rebuilder.addPart(2, totalLength - 2, buf(rest)));

        ByteBuffer result = rebuilder.rebuild();
        assertEquals(totalLength, result.remaining());
        byte[] resultBytes = drain(result);
        assertEquals((byte) 0x00, resultBytes[0]);
        assertEquals((byte) totalLength, resultBytes[1]);
        for (int i = 2; i < totalLength; i++) {
            assertEquals(rest[i - 2], resultBytes[i]);
        }
    }

    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    // Not complete until gap at offset 0 is filled
    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /**
     * RFC 9001 В§4.1.3 вЂ“ TLS requires contiguous data from offset 0.  Having all bytes
     * except the very first segment must NOT be considered complete.
     */
    @Test
    void missingStartSegment_notComplete() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        rebuilder.setExpectedLength(9);

        // Everything except bytes 0-2
        rebuilder.addPart(3, 6, buf(sequential(3, 6)));
        assertFalse(rebuilder.isComplete(), "Frame cannot be complete without offset-0 data");

        // Now fill the start
        assertTrue(rebuilder.addPart(0, 3, buf(sequential(0, 3))));
    }

    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    // rebuild() result correctness with various orderings
    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /**
     * Verify rebuild() assembles bytes correctly after reverse-order delivery.
     */
    @Test
    void rebuild_reverseOrder_correctContent() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        int total = 15;
        rebuilder.setExpectedLength(total);

        // Deliver five 3-byte chunks in reverse order
        for (int i = 4; i >= 0; i--) {
            rebuilder.addPart(i * 3, 3, buf(sequential(i * 3, 3)));
        }

        assertTrue(rebuilder.isComplete());
        assertArrayEquals(sequential(0, total), drain(rebuilder.rebuild()));
    }

    /**
     * rebuild() must return a buffer whose position is 0 and limit equals expectedLength.
     */
    @Test
    void rebuild_bufferPositionAndLimit() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        rebuilder.setExpectedLength(5);
        rebuilder.addPart(0, 5, buf(sequential(0, 5)));

        ByteBuffer result = rebuilder.rebuild();
        assertEquals(0, result.position(), "Buffer position must be 0 after rebuild");
        assertEquals(5, result.limit(), "Buffer limit must equal expectedLength");
    }

    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    // Error / contract violations
    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /**
     * Calling rebuild() before the frame is complete must throw IllegalStateException.
     */
    @Test
    void rebuild_beforeComplete_throwsIllegalState() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        rebuilder.setExpectedLength(10);
        rebuilder.addPart(0, 5, buf(sequential(0, 5)));

        assertThrows(IllegalStateException.class, rebuilder::rebuild,
            "rebuild() must throw before frame is complete");
    }

    /**
     * Calling setExpectedLength a second time must throw IllegalStateException.
     * (Prevents arbitrary length mutation mid-stream.)
     */
    @Test
    void setExpectedLength_twice_throwsIllegalState() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        rebuilder.setExpectedLength(10);

        assertThrows(IllegalStateException.class, () -> rebuilder.setExpectedLength(20));
    }

    /**
     * setExpectedLength with zero or negative must throw IllegalArgumentException.
     */
    @Test
    void setExpectedLength_nonPositive_throwsIllegalArgument() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();

        assertThrows(IllegalArgumentException.class, () -> rebuilder.setExpectedLength(0));
        assertThrows(IllegalArgumentException.class, () -> new CryptoFrameRebuilder().setExpectedLength(-1));
    }

    /**
     * addPart with negative offset must throw IllegalStateException.
     */
    @Test
    void addPart_negativeOffset_throwsIllegalState() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        rebuilder.setExpectedLength(10);

        assertThrows(IllegalStateException.class,
            () -> rebuilder.addPart(-1, 5, buf(sequential(0, 5))));
    }

    /**
     * addPart with zero length must throw IllegalStateException.
     */
    @Test
    void addPart_zeroLength_throwsIllegalState() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        rebuilder.setExpectedLength(10);

        assertThrows(IllegalStateException.class,
            () -> rebuilder.addPart(0, 0, buf(new byte[0])));
    }

    /**
     * addPart with a ByteBuffer that has fewer remaining bytes than declared length
     * must throw IllegalStateException.
     */
    @Test
    void addPart_insufficientBuffer_throwsIllegalState() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        rebuilder.setExpectedLength(10);

        PoolBuffer tooSmall = new BorrowedPoolBuffer(mock(RootPoolBuffer.class), ByteBuffer.wrap(new byte[3]));
        assertThrows(IllegalStateException.class,
            () -> rebuilder.addPart(0, 5, tooSmall));
    }

    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    // DoS budget enforcement (RFC 9000 flow-control motivation)
    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /**
     * RFC 9000 В§4 motivates limiting unbounded buffering to prevent DoS.
     * Staging data beyond the built-in 16 384-byte budget must be rejected.
     */
    @Test
    void addPart_beyondDosBudget_throwsIllegalState() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();

        int overBudget = 16385;
        byte[] bigPayload = new byte[overBudget];
        Arrays.fill(bigPayload, (byte) 0xAB);

        assertThrows(IllegalStateException.class,
            () -> rebuilder.addPart(0, overBudget, buf(bigPayload)));
    }

    /**
     * Data ending exactly at the 16 384-byte boundary must be accepted (boundary check
     * uses >, not >=).
     */
    @Test
    void addPart_exactlyAtDosBudget_accepted() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();
        rebuilder.setExpectedLength(16384);

        byte[] maxPayload = new byte[16384];
        assertTrue(rebuilder.addPart(0, 16384, buf(maxPayload)));
    }

    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    // isComplete semantics without setExpectedLength
    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /**
     * isComplete must never return true when setExpectedLength has not been called,
     * even if data covering any large range has been buffered.
     */
    @Test
    void isComplete_withoutExpectedLength_alwaysFalse() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();

        rebuilder.addPart(0, 5, buf(sequential(0, 5)));
        assertFalse(rebuilder.isComplete(),
            "isComplete must be false without a known expectedLength");
    }

    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    // getExpectedLength
    // в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /**
     * getExpectedLength returns -1 before setExpectedLength is called, and the
     * correct value afterwards.
     */
    @Test
    void getExpectedLength_beforeAndAfterSet() {
        CryptoFrameRebuilder rebuilder = new CryptoFrameRebuilder();

        assertEquals(-1, rebuilder.getExpectedLength(), "Should be -1 before set");
        rebuilder.setExpectedLength(42);
        assertEquals(42, rebuilder.getExpectedLength());
    }
}

