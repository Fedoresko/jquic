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
package org.jquic.quic;

import org.jquic.quic.buffers.BufferPool;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.crypto.CipherMode;
import org.jquic.quic.crypto.NativeCrypto;
import org.jquic.quic.crypto.QuicCrypto;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.*;

public class QuicPacketHeaderTest {

    @Test
    public void testParseInitialHeaderNoProtection() {
        byte[] dcid = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] scid = new byte[] {8, 7, 6, 5, 4, 3, 2, 1};
        byte pnLen = 2; // 2 bytes
        byte flags = (byte) (0xC0 | ((pnLen - 1) & 0x03)); // Long header, Initial, pnLen=2
        int version = 1;
        long payloadLen = 100;
        long pn = 12345;
        long largestPn = 12300;

        ByteBuffer buf = ByteBuffer.allocate(100);
        buf.put(flags);
        buf.putInt(version);
        buf.put((byte) dcid.length);
        buf.put(dcid);
        buf.put((byte) scid.length);
        buf.put(scid);
        QuicVarint.write(buf, 0); // Token length 0
        QuicVarint.write(buf, payloadLen);
        // Write PN (big endian)
        buf.putShort((short) (pn & 0xFFFF));
        buf.flip();

        QuicPacketHeader header = QuicPacketHeader.parse(buf, null, largestPn);

        assertNotNull(header);
        assertEquals(QuicPacketHeader.PacketType.INITIAL, header.packetType);
        assertEquals(version, header.version);
        assertArrayEquals(dcid, header.destinationCid);
        assertArrayEquals(scid, header.sourceCid);
        assertEquals(payloadLen, header.payloadLength);
        assertEquals(pn, header.packetNumber);
        assertEquals(pnLen, header.pnLength);
    }

    @Test
    public void testParseHandshakeHeaderNoProtection() {
        byte[] dcid = new byte[] {(byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44};
        byte[] scid = new byte[] {(byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88};
        byte flags = (byte) (0xC0 | (0x02 << 4)); // Long header, Handshake, pnLen=1
        int version = 1;
        long payloadLen = 50;
        long pn = 500;
        long largestPn = 450;

        ByteBuffer buf = ByteBuffer.allocate(100);
        buf.put(flags);
        buf.putInt(version);
        buf.put((byte) dcid.length);
        buf.put(dcid);
        buf.put((byte) scid.length);
        buf.put(scid);
        QuicVarint.write(buf, payloadLen);
        buf.put((byte) (pn & 0xFF));
        buf.flip();

        QuicPacketHeader header = QuicPacketHeader.parse(buf, null, largestPn);

        assertNotNull(header);
        assertEquals(QuicPacketHeader.PacketType.HANDSHAKE, header.packetType);
        assertArrayEquals(dcid, header.destinationCid);
        assertArrayEquals(scid, header.sourceCid);
        assertEquals(payloadLen, header.payloadLength);
        assertEquals(pn, header.packetNumber);
    }

    @Test
    public void testParseZeroRttHeaderNoProtection() {
        byte[] dcid = new byte[] {1, 2, 3, 4};
        byte[] scid = new byte[] {5, 6, 7, 8};
        byte pnLen = 2;
        byte flags = (byte) (0xC0 | (0x01 << 4) | ((pnLen - 1) & 0x03)); // Long header, 0-RTT
        int version = 1;
        long payloadLen = 80;
        long pn = 1000;
        long largestPn = 900;

        ByteBuffer buf = ByteBuffer.allocate(100);
        buf.put(flags);
        buf.putInt(version);
        buf.put((byte) dcid.length);
        buf.put(dcid);
        buf.put((byte) scid.length);
        buf.put(scid);
        QuicVarint.write(buf, payloadLen);
        buf.putShort((short) (pn & 0xFFFF));
        buf.flip();

        QuicPacketHeader header = QuicPacketHeader.parse(buf, null, largestPn);

        assertNotNull(header);
        assertEquals(QuicPacketHeader.PacketType.ZERO_RTT, header.packetType);
        assertEquals(pn, header.packetNumber);
    }

    @Test
    public void testParseOneRttHeaderNoProtection() {
        byte[] dcid = new byte[] {1, 1, 1, 1, 2, 2, 2, 2};
        byte pnLen = 4;
        byte flags = (byte) (0x40 | ((pnLen - 1) & 0x03)); // Short header, pnLen=4
        long pn = 0x12345678L;
        long largestPn = 0x12345600L;

        ByteBuffer buf = ByteBuffer.allocate(100);
        buf.put(flags);
        buf.put(dcid);
        buf.putInt((int) pn);
        buf.flip();

        QuicPacketHeader header = QuicPacketHeader.parse(buf, null, largestPn);

        assertNotNull(header);
        assertEquals(QuicPacketHeader.PacketType.ONE_RTT, header.packetType);
        assertArrayEquals(dcid, header.destinationCid);
        assertEquals(pn, header.packetNumber);
    }

    @Test
    public void testDecodePacketNumber() {
        // Examples from RFC 9000 Appendix A.3
        
        // At the beginning of the connection, the largest successfully
        // unmasked packet number is 0xabe8b3.
        long largestPn = 0xabe8b3L;
        
        // A packet is received with a 16-bit truncated packet number of 0xac5c.
        long truncatedPn = 0xac5cL;
        int pnNbits = 16;
        
        long decodedPn = QuicPacketHeader.decodePacketNumber(largestPn, truncatedPn, pnNbits);
        assertEquals(0xabac5cL, decodedPn);

        // Test near window boundaries
        // If truncatedPn is smaller but close to largestPn (within pnHalfWin)
        largestPn = 1000;
        pnNbits = 8; // pnHalfWin = 128
        truncatedPn = (1000 - 10) & 0xFF; 
        assertEquals(990, QuicPacketHeader.decodePacketNumber(largestPn, truncatedPn, pnNbits));

        // If truncatedPn is larger but close to largestPn
        truncatedPn = (1000 + 10) & 0xFF;
        assertEquals(1010, QuicPacketHeader.decodePacketNumber(largestPn, truncatedPn, pnNbits));

        // Test wrapping - next window
        largestPn = 200;
        truncatedPn = 50;
        // expectedPn = 201
        // candidatePn = (201 & ~0xFF) | 50 = 0 | 50 = 50.
        // candidatePn (50) <= 201 - 128 (73) is true.
        // decoded should be 50 + 256 = 306.
        assertEquals(306, QuicPacketHeader.decodePacketNumber(largestPn, truncatedPn, pnNbits));

        // Test wrapping - previous window
        largestPn = 300;
        truncatedPn = 250;
        // expectedPn = 301
        // candidatePn = (301 & ~0xFF) | 250 = 256 | 250 = 506.
        // candidatePn (506) > 301 + 128 (429) is true.
        // decoded should be 506 - 256 = 250.
        assertEquals(250, QuicPacketHeader.decodePacketNumber(largestPn, truncatedPn, pnNbits));
        
        // Test edge case: largestPn = -1 (nothing received yet)
        largestPn = -1;
        pnNbits = 8;
        truncatedPn = 0;
        assertEquals(0, QuicPacketHeader.decodePacketNumber(largestPn, truncatedPn, pnNbits));
    }

    @Test
    public void testParseInitialHeaderWithProtection() throws Exception {
        byte[] dcid = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] scid = new byte[] {8, 7, 6, 5, 4, 3, 2, 1};
        byte pnLen = 2;
        int version = 1;
        long payloadLen = 100;
        long pn = 12345;
        long largestPn = 12300;

        // Header Protection Key
        byte[] hpKey = new byte[16]; // all zeros for test
        SecretKeySpec keySpec = new SecretKeySpec(hpKey, "AES");
        Cipher hpCipher = Cipher.getInstance("AES/ECB/NoPadding");
        hpCipher.init(Cipher.ENCRYPT_MODE, keySpec);

        ByteBuffer buf = ByteBuffer.allocate(100);
        int startPos = buf.position();
        byte originalFlags = (byte) (0xC0 | ((pnLen - 1) & 0x03));
        buf.put(originalFlags);
        buf.putInt(version);
        buf.put((byte) dcid.length);
        buf.put(dcid);
        buf.put((byte) scid.length);
        buf.put(scid);
        QuicVarint.write(buf, 0); 
        QuicVarint.write(buf, payloadLen);
        
        int pnPos = buf.position();
        buf.putShort((short) (pn & 0xFFFF));
        
        // Add at least 4 + 16 bytes for sample
        byte[] sampleData = new byte[20];
        for(int i=0; i<20; i++) sampleData[i] = (byte) i;
        buf.put(sampleData);
        buf.flip();

        // Calculate mask
        byte[] sample = new byte[16];
        buf.duplicate().position(pnPos + 4).get(sample);
        byte[] mask = hpCipher.doFinal(sample);

        // Apply protection to flags
        byte protectedFlags = (byte) (originalFlags ^ (mask[0] & 0x0F));
        buf.put(startPos, protectedFlags);

        // Apply protection to PN
        for (int i = 0; i < pnLen; i++) {
            byte originalByte = buf.get(pnPos + i);
            buf.put(pnPos + i, (byte) (originalByte ^ mask[1 + i]));
        }

        ByteBuffer hpSeg = ByteBuffer.allocateDirect(hpKey.length).put(hpKey).flip();
        // Now parse it
        QuicPacketHeader header = QuicPacketHeader.parse(buf, new NativeCrypto(new QuicCrypto.PacketProtectionKeysWithHP(null, null, hpSeg), CipherMode.TLS_AES_128_GCM_SHA256_ID), largestPn);

        assertNotNull(header);
        assertEquals(pn, header.packetNumber);
        assertEquals(originalFlags, header.flags); // header.flags should be unmasked
    }

    @Test
    public void testParseSummary() {
        byte[] dcid = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
        byte flags = (byte) 0xC0; // Long, Initial
        ByteBuffer buf = ByteBuffer.allocate(100);
        buf.put(flags);
        buf.putInt(1); // version
        buf.put((byte) dcid.length);
        buf.put(dcid);
        buf.put((byte) 0); // scid length 0
        buf.flip();

        QuicPacketHeader.PacketSummary summary = QuicPacketHeader.parseSummary(buf);
        assertNotNull(summary);
        assertEquals(QuicPacketHeader.PacketType.INITIAL, summary.type());
        assertArrayEquals(dcid, summary.dcid());
        
        // Short header
        buf.clear();
        flags = (byte) 0x40;
        buf.put(flags);
        buf.put(dcid);
        buf.flip();
        
        summary = QuicPacketHeader.parseSummary(buf);
        assertNotNull(summary);
        assertEquals(QuicPacketHeader.PacketType.ONE_RTT, summary.type());
        assertArrayEquals(dcid, summary.dcid());
    }

    @Test
    public void testParseMalformedHeader() {
        // Truncated header
        ByteBuffer buf = ByteBuffer.allocate(3);
        buf.put((byte) 0xC0); // Long header
        buf.putShort((short) 1);
        buf.flip();

        assertNull(QuicPacketHeader.parse(buf, null, 0));

        // Invalid long header flags (missing bit 6)
        buf = ByteBuffer.allocate(20);
        buf.put((byte) 0x80); 
        buf.flip();
        // parseSummary checks bit 6
        assertNull(QuicPacketHeader.parseSummary(buf));
    }

    @Test
    public void testEncodePacketNumber() {
        // RFC 9000: The number of bits required to represent 2 * (packet_number - largest_acked)
        
        // case 1: delta = 1, delta*2 = 2 <= 2^8 -> 1 byte
        assertEquals(1, QuicPacketHeader.calculatePnLength(11, 10));
        
        // case 2: delta = 127, delta*2 = 254 <= 2^8 -> 1 byte
        assertEquals(1, QuicPacketHeader.calculatePnLength(137, 10));
        
        // case 3: delta = 128, delta*2 = 256 <= 2^8 -> 1 byte (Wait, 2^8 is 256. My code has <= (1L << 8))
        // (1L << 8) is 256. So 256 <= 256 is true.
        assertEquals(1, QuicPacketHeader.calculatePnLength(138, 10));

        // case 4: delta = 129, delta*2 = 258 > 256 -> 2 bytes
        assertEquals(2, QuicPacketHeader.calculatePnLength(139, 10));
        
        // case 5: delta = 32767, delta*2 = 65534 <= 2^16 -> 2 bytes
        assertEquals(2, QuicPacketHeader.calculatePnLength(32767, 0));
        
        // case 6: delta = 32768, delta*2 = 65536 <= 2^16 -> 2 bytes
        assertEquals(2, QuicPacketHeader.calculatePnLength(32768, 0));
        
        // case 7: delta = 32769, delta*2 = 65538 > 65536 -> 3 bytes
        assertEquals(3, QuicPacketHeader.calculatePnLength(32769, 0));
    }

    @Test
    public void testTruncatePacketNumber() {
        long pn = 0x12345678L;
        assertEquals(0x78L, QuicPacketHeader.truncatePacketNumber(pn, 1));
        assertEquals(0x5678L, QuicPacketHeader.truncatePacketNumber(pn, 2));
        assertEquals(0x345678L, QuicPacketHeader.truncatePacketNumber(pn, 3));
        assertEquals(0x12345678L, QuicPacketHeader.truncatePacketNumber(pn, 4));
    }

    @Test
    public void testHeaderWritingAndPacketNumberEncoding() {
        byte[] dcid = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] scid = new byte[]{8, 7, 6, 5, 4, 3, 2, 1};
        byte[] token = new byte[]{0x0A, 0x0B};

        // 1. Long Header (Initial)
        QuicPacketHeader header = new QuicPacketHeader(
                new QuicPacketHeader.PacketNumber(2, 0x12345678L, (byte) 0),
                QuicVersion.QUIC_VERSION_1, dcid, scid, QuicPacketHeader.PacketType.INITIAL, token, 100, (byte) 0);

        ByteBuffer buf = ByteBuffer.allocate(header.headerLength);
        header.write(buf);
        buf.flip();

        // Check flags: 0xC0 (Long, Fixed) | 0x00 (Initial) | 0x01 (2 bytes PN) = 0xC1
        assertEquals((byte) 0xC1, buf.get());
        assertEquals(0x00000001, buf.getInt());
        assertEquals((byte) dcid.length, buf.get());
        byte[] readDcid = new byte[dcid.length];
        buf.get(readDcid);
        assertArrayEquals(dcid, readDcid);

        assertEquals((byte) scid.length, buf.get());
        byte[] readScid = new byte[scid.length];
        buf.get(readScid);
        assertArrayEquals(scid, readScid);

        assertEquals(2, QuicVarint.read(buf));
        byte[] readToken = new byte[token.length];
        buf.get(readToken);
        assertArrayEquals(token, readToken);

        assertEquals(100, QuicVarint.read(buf));

        // Packet number (truncated 0x12345678 to 2 bytes -> 0x5678)
        assertEquals((short) 0x5678, buf.getShort());
        assertFalse(buf.hasRemaining());

        // 2. Short Header
        buf = ByteBuffer.allocate(100);
        header = new QuicPacketHeader(
                new QuicPacketHeader.PacketNumber(1, 0x12345678L, (byte) 0),
                QuicVersion.UNKNOWN, dcid, null, QuicPacketHeader.PacketType.ONE_RTT, null, -1, (byte) 1);
        header.write(buf);
        buf.flip();

        // Check flags: 0x40 (Fixed) | 0x04 (KeyPhase 1) | 0x00 (1 byte PN) = 0x44
        assertEquals((byte) 0x44, buf.get());
        readDcid = new byte[dcid.length];
        buf.get(readDcid);
        assertArrayEquals(dcid, readDcid);
        // Packet number (truncated 0x12345678 to 1 byte -> 0x78)
        assertEquals((byte) 0x78, buf.get());
        assertFalse(buf.hasRemaining());
    }

    @Test
    public void testPacketNumberPingPong() {
        long[] testPacketNumbers = {1, 100, 1000, 0x12345678L, 0x3FFFFFFFFFFFFFFFL};
        long largestAcked = 0;

        for (long pn : testPacketNumbers) {
            int pnLen = QuicPacketHeader.calculatePnLength(pn, largestAcked);
            long truncatedPn = QuicPacketHeader.truncatePacketNumber(pn, pnLen);

            long decodedPn = QuicPacketHeader.decodePacketNumber(largestAcked, truncatedPn, pnLen * 8);
            
            // Note: If delta is > 2^31, 4-byte encoding is not enough to recover the full PN.
            // RFC 9000 says: "The number of bits ... must be at least ... 2 * (packet_number - largest_acked)"
            // If delta is huge, we can't satisfy this with 4 bytes.
            long delta = pn - largestAcked;
            if (delta < (1L << 31)) {
                assertEquals(pn, decodedPn, "Failed for PN: " + pn + " with largestAcked: " + largestAcked);
            }

            largestAcked = pn; // Advance largestAcked for next "ping-pong"
        }

        // Test with gaps
        largestAcked = 1000;
        long pn = 1000 + 127; // 1 byte PN can handle delta up to 128 (since 2*delta <= 256)
        int pnLen = QuicPacketHeader.calculatePnLength(pn, largestAcked);
        assertEquals(1, pnLen);
        long truncatedPn = QuicPacketHeader.truncatePacketNumber(pn, pnLen);
        assertEquals(pn, QuicPacketHeader.decodePacketNumber(largestAcked, truncatedPn, pnLen * 8));

        pn = 1000 + 129; // 2 byte PN required
        pnLen = QuicPacketHeader.calculatePnLength(pn, largestAcked);
        assertEquals(2, pnLen);
        truncatedPn = QuicPacketHeader.truncatePacketNumber(pn, pnLen);
        assertEquals(pn, QuicPacketHeader.decodePacketNumber(largestAcked, truncatedPn, pnLen * 8));
    }

    @Test
    public void testRealPingPongWithParsing() {
        byte[] dcid = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        long clientPn = 0;
        long serverPn = 0;
        long clientLargestSeen = -1;
        long serverLargestSeen = -1;

        // Simulate 5 exchanges
        for (int i = 0; i < 5; i++) {
            // 1. Client sends to Server
            clientPn += (1 + (int)(Math.random() * 10));
            int pnLen = QuicPacketHeader.calculatePnLength(clientPn, clientLargestSeen == -1 ? 0 : clientLargestSeen);
            QuicPacketHeader clientHeader = new QuicPacketHeader(
                    new QuicPacketHeader.PacketNumber(pnLen, clientPn, (byte) 0),
                    QuicVersion.UNKNOWN, dcid, null, QuicPacketHeader.PacketType.ONE_RTT, null, -1, (byte) 0);
            
            ByteBuffer buf = ByteBuffer.allocate(clientHeader.headerLength + 10); // + some payload space
            clientHeader.write(buf);
            buf.put(new byte[10]); // dummy payload
            buf.flip();

            // Server parses
            QuicPacketHeader parsedByServer = QuicPacketHeader.parse(buf, null, serverLargestSeen == -1 ? 0 : serverLargestSeen);
            assertNotNull(parsedByServer);
            assertEquals(clientPn, parsedByServer.packetNumber, "Server failed to decode client PN at exchange " + i);
            serverLargestSeen = Math.max(serverLargestSeen, parsedByServer.packetNumber);

            // 2. Server sends to Client
            serverPn += (1 + (int)(Math.random() * 10));
            pnLen = QuicPacketHeader.calculatePnLength(serverPn, serverLargestSeen == -1 ? 0 : serverLargestSeen);
            QuicPacketHeader serverHeader = new QuicPacketHeader(
                    new QuicPacketHeader.PacketNumber(pnLen, serverPn, (byte) 0),
                    QuicVersion.UNKNOWN, dcid, null, QuicPacketHeader.PacketType.ONE_RTT, null, -1, (byte) 0);
            
            buf = ByteBuffer.allocate(serverHeader.headerLength + 10);
            serverHeader.write(buf);
            buf.put(new byte[10]);
            buf.flip();

            // Client parses
            QuicPacketHeader parsedByClient = QuicPacketHeader.parse(buf, null, clientLargestSeen == -1 ? 0 : clientLargestSeen);
            assertNotNull(parsedByClient);
            assertEquals(serverPn, parsedByClient.packetNumber, "Client failed to decode server PN at exchange " + i);
            clientLargestSeen = Math.max(clientLargestSeen, parsedByClient.packetNumber);
        }
    }

    @Test
    public void testVersionNegotiation() {
        byte[] dcid = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] scid = new byte[] {8, 7, 6, 5, 4, 3, 2, 1};
        int unsupportedVersion = 0x12345678;

        // Simulate a Long Header packet with unsupported version
        ByteBuffer buf = ByteBuffer.allocate(100);
        buf.put((byte) 0xC0); // Long header
        buf.putInt(unsupportedVersion);
        buf.put((byte) dcid.length);
        buf.put(dcid);
        buf.put((byte) scid.length);
        buf.put(scid);
        buf.flip();

        QuicPacketHeader.PacketSummary summary = QuicPacketHeader.parseSummary(buf);
        assertNotNull(summary);
        assertEquals(QuicVersion.UNKNOWN, summary.version());
        assertArrayEquals(dcid, summary.dcid());
        assertArrayEquals(scid, summary.scid());

        // Now test building a Version Negotiation packet
        PoolBuffer vnPoolBuffer = QuicPacketBuilder.buildVersionNegotiationPacket(new BufferPool(), scid, dcid);
        ByteBuffer vnBuf = vnPoolBuffer.buf();

        byte firstByte = vnBuf.get();
        assertTrue((firstByte & 0x80) != 0, "VN packet must have header form set to 1");
        assertTrue((firstByte & 0x40) != 0, "Fixed bit should be set in our implementation");

        assertEquals(0, vnBuf.getInt(), "Version must be 0 for VN packet");

        assertEquals((byte) scid.length, vnBuf.get());
        byte[] readDcid = new byte[scid.length];
        vnBuf.get(readDcid);
        assertArrayEquals(scid, readDcid, "VN DCID should be received SCID");

        assertEquals((byte) dcid.length, vnBuf.get());
        byte[] readScid = new byte[dcid.length];
        vnBuf.get(readScid);
        assertArrayEquals(dcid, readScid, "VN SCID should be received DCID");

        assertEquals(QuicVersion.QUIC_VERSION_1.val, vnBuf.getInt(), "Supported version 1 must be present");
        assertEquals(QuicVersion.QUIC_VERSION_2.val, vnBuf.getInt(), "Supported version 2 must be present");
        assertFalse(vnBuf.hasRemaining());

        vnPoolBuffer.release();
    }

    @Test
    public void testQuicV2PacketTypeParsing() {
        byte[] dcid = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] scid = new byte[]{8, 7, 6, 5, 4, 3, 2, 1};
        
        // RFC 9369 QUIC V2 Long Header Types:
        // Initial: 0b01 (0x10)
        // Zero-RTT: 0b10 (0x20)
        // Handshake: 0b11 (0x30)
        // Retry: 0b00 (0x00)

        // 1. Initial
        byte flags = (byte) (0x80 | 0x40 | 0x10); // Long, Fixed, Initial (V2)
        ByteBuffer buf = ByteBuffer.allocate(100);
        buf.put(flags);
        buf.putInt(QuicVersion.QUIC_VERSION_2.val);
        buf.put((byte) dcid.length).put(dcid);
        buf.put((byte) scid.length).put(scid);
        buf.flip();

        QuicPacketHeader.PacketSummary summary = QuicPacketHeader.parseSummary(buf);
        assertNotNull(summary);
        assertEquals(QuicPacketHeader.PacketType.INITIAL, summary.type());
        assertEquals(QuicVersion.QUIC_VERSION_2, summary.version());

        // 2. Handshake
        buf.clear();
        flags = (byte) (0x80 | 0x40 | 0x30); // Long, Fixed, Handshake (V2)
        buf.put(flags);
        buf.putInt(QuicVersion.QUIC_VERSION_2.val);
        buf.put((byte) dcid.length).put(dcid);
        buf.put((byte) scid.length).put(scid);
        buf.flip();

        summary = QuicPacketHeader.parseSummary(buf);
        assertNotNull(summary);
        assertEquals(QuicPacketHeader.PacketType.HANDSHAKE, summary.type());

        // 3. Zero-RTT
        buf.clear();
        flags = (byte) (0x80 | 0x40 | 0x20); // Long, Fixed, Zero-RTT (V2)
        buf.put(flags);
        buf.putInt(QuicVersion.QUIC_VERSION_2.val);
        buf.put((byte) dcid.length).put(dcid);
        buf.put((byte) scid.length).put(scid);
        buf.flip();

        summary = QuicPacketHeader.parseSummary(buf);
        assertNotNull(summary);
        assertEquals(QuicPacketHeader.PacketType.ZERO_RTT, summary.type());

        // 4. Retry
        buf.clear();
        flags = (byte) (0x80 | 0x40); // Long, Fixed, Retry (V2)
        buf.put(flags);
        buf.putInt(QuicVersion.QUIC_VERSION_2.val);
        buf.put((byte) dcid.length).put(dcid);
        buf.put((byte) scid.length).put(scid);
        buf.flip();

        summary = QuicPacketHeader.parseSummary(buf);
        assertNotNull(summary);
        assertEquals(QuicPacketHeader.PacketType.RETRY, summary.type());
    }

    @Test
    public void testQuicV2HeaderWriting() {
        byte[] dcid = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] scid = new byte[]{8, 7, 6, 5, 4, 3, 2, 1};

        // Test Initial packet for QUIC V2
        QuicPacketHeader header = new QuicPacketHeader(
                new QuicPacketHeader.PacketNumber(1, 100, (byte) 0),
                QuicVersion.QUIC_VERSION_2, dcid, scid, QuicPacketHeader.PacketType.INITIAL, new byte[0], 0, (byte) 0);

        ByteBuffer buf = ByteBuffer.allocate(header.headerLength);
        header.write(buf);
        buf.flip();

        // Flags should be 0x80 | 0x40 | 0x10 (Initial V2) | 0x00 (1 byte PN) = 0xD0
        assertEquals((byte) 0xD0, buf.get());
        assertEquals(QuicVersion.QUIC_VERSION_2.val, buf.getInt());
        
        // Test Handshake packet for QUIC V2
        header = new QuicPacketHeader(
                new QuicPacketHeader.PacketNumber(1, 101, (byte) 0),
                QuicVersion.QUIC_VERSION_2, dcid, scid, QuicPacketHeader.PacketType.HANDSHAKE, null, 0, (byte) 0);

        buf = ByteBuffer.allocate(header.headerLength);
        header.write(buf);
        buf.flip();

        // Flags should be 0x80 | 0x40 | 0x30 (Handshake V2) | 0x00 (1 byte PN) = 0xF0
        assertEquals((byte) 0xF0, buf.get());
    }
}
