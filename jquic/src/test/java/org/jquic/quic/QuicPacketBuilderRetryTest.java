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

import org.jquic.quic.crypto.NativeCrypto;
import org.jquic.quic.crypto.QuicCrypto;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class QuicPacketBuilderRetryTest {

    @Test
    void testBuildRetryPacketV1() throws Exception {
        byte[] dcid = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] scid = new byte[]{8, 7, 6, 5, 4, 3, 2, 1};
        byte[] tokenBytes = new byte[]{0x11, 0x22, 0x33, 0x44};
        byte[] odcid = new byte[]{0x0a, 0x0b, 0x0c, 0x0d};

        int headerLen = 1 + 4 + 1 + dcid.length + 1 + scid.length;
        int integrityTagLen = 16;
        ByteBuffer buffer = ByteBuffer.allocateDirect(100 + headerLen + tokenBytes.length + integrityTagLen);
        buffer.position(100);
        buffer.put(tokenBytes);
        buffer.flip();
        buffer.position(100);

        try (NativeCrypto integrityCrypto = QuicCrypto.getRetryIntegrityCryptoV1()) {
            QuicPacketBuilder.buildRetryPacket(
                    buffer,
                    QuicVersion.QUIC_VERSION_1,
                    dcid,
                    scid,
                    odcid,
                    integrityCrypto
            );
        }

        assertNotNull(buffer);

        ByteBuffer b = ByteBuffer.allocate(buffer.remaining());
        b.put(buffer.duplicate()).flip();

        System.out.println(HexFormat.of().formatHex(b.array(), b.position(), b.limit()));

        // Verify Header
        byte flags = buffer.get();
        assertTrue((flags & 0x80) != 0, "Long header bit must be set");
        assertEquals(0x03, (flags >> 4) & 0x03, "Packet type must be Retry");


        assertEquals(QuicVersion.QUIC_VERSION_1.val, buffer.getInt());

        int dcidLen = buffer.get() & 0xFF;
        assertEquals(dcid.length, dcidLen);
        byte[] actualDcid = new byte[dcidLen];
        buffer.get(actualDcid);
        assertArrayEquals(dcid, actualDcid);

        int scidLen = buffer.get() & 0xFF;
        assertEquals(scid.length, scidLen);
        byte[] actualScid = new byte[scidLen];
        buffer.get(actualScid);
        assertArrayEquals(scid, actualScid);

        byte[] actualToken = new byte[tokenBytes.length];
        buffer.get(actualToken);
        assertArrayEquals(tokenBytes, actualToken);

        // Verify ODCID is prepended correctly in the same buffer (before the returned packet)
        int packetStart = 100 - headerLen;
        int pseudoHeaderLen = 1 + odcid.length;
        int pseudoStart = packetStart - pseudoHeaderLen;

        ByteBuffer pseudoHeader = buffer.duplicate().clear();
        pseudoHeader.position(pseudoStart);
        assertEquals(odcid.length, pseudoHeader.get() & 0xFF);
        byte[] actualOdcid = new byte[odcid.length];
        pseudoHeader.get(actualOdcid);
        assertArrayEquals(odcid, actualOdcid);

        assertEquals(16, buffer.remaining(), "Integrity Tag must be 16 bytes");
    }

    @Test
    void testBuildRetryPacketV2() throws Exception {
        byte[] dcid = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] scid = new byte[]{8, 7, 6, 5, 4, 3, 2, 1};
        byte[] tokenBytes = new byte[]{(byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88};
        byte[] odcid = new byte[]{0x0e, 0x0f, 0x10, 0x11};

        int headerLen = 1 + 4 + 1 + dcid.length + 1 + scid.length;
        int integrityTagLen = 16;
        ByteBuffer buffer = ByteBuffer.allocateDirect(100 + headerLen + tokenBytes.length + integrityTagLen);
        buffer.position(100);
        buffer.put(tokenBytes);
        buffer.flip();
        buffer.position(100);

        try (NativeCrypto integrityCrypto = QuicCrypto.getRetryIntegrityCryptoV2()) {
            QuicPacketBuilder.buildRetryPacket(
                    buffer,
                    QuicVersion.QUIC_VERSION_2,
                    dcid,
                    scid,
                    odcid,
                    integrityCrypto
            );
        }

        assertEquals(QuicVersion.QUIC_VERSION_2.val, buffer.getInt(buffer.position() + 1));
    }
}
