package org.fmalyshev.quic;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for SelectorThread.
 * Tests the full lifecycle of connections through processPacket() with real QUIC datagrams.
 */
class SelectorThreadTest {

    private SelectorThread selectorThread;
    private DatagramChannel channel;

    @BeforeEach
    void setUp() throws Exception {
        // Create SelectorThread components
        channel = DatagramChannel.open();
        ConcurrentHashMap<Long, Integer> cidToSelectorMap = new ConcurrentHashMap<>();

        selectorThread = new SelectorThread(0, channel, cidToSelectorMap);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (channel != null && channel.isOpen()) {
            channel.close();
        }
    }

    @Test
    @DisplayName("Test skipPacket correctly advances buffer for long and short headers")
    void testSkipPacket() {
        // 1. Test Long Header (Initial packet)
        // flags(1) | version(4) | dcid_len(1) | dcid(8) | scid_len(1) | scid(8) | token_len(1) | token(0) | length(1) | payload(10)
        // Total expected skip: 1+4+1+8+1+8+1+0+1+10 = 35 bytes
        ByteBuffer longHeader = ByteBuffer.allocate(100);
        longHeader.put((byte) 0xC0); // Initial
        longHeader.putInt(1); // version
        longHeader.put((byte) 8); // dcid len
        longHeader.putLong(12345L); // dcid
        longHeader.put((byte) 8); // scid len
        longHeader.putLong(67890L); // scid
        longHeader.put((byte) 0); // token len varint (0)
        longHeader.put((byte) 10); // length varint (10)
        longHeader.put(new byte[10]); // payload
        longHeader.flip();

        int startPos = longHeader.position();
        SelectorThread.skipPacket(longHeader);
        assertEquals(startPos + 35, longHeader.position(), "Should skip entire long header packet");

        // 2. Test Short Header (1-RTT)
        // Short header packets consume the rest of the datagram
        ByteBuffer shortHeader = ByteBuffer.allocate(100);
        shortHeader.put((byte) 0x40); // Short header
        shortHeader.putLong(12345L); // dcid
        shortHeader.put(new byte[20]); // some payload
        shortHeader.flip();

        SelectorThread.skipPacket(shortHeader);
        assertEquals(shortHeader.limit(), shortHeader.position(), "Short header should consume rest of datagram");
    }

    // Helper methods
}
