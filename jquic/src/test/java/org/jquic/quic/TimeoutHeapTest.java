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

import org.jctools.queues.SpscLinkedQueue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.net.InetSocketAddress;

import static org.junit.jupiter.api.Assertions.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for QuicConnectionTimeoutHeap.
 * Tests the min-heap data structure used for efficient timeout-based connection eviction.
 */
class TimeoutHeapTest {

    private TimeoutHeap<QuicConnection> timeoutHeap;
    private SelectorThread selectorMock;
    MockedStatic<QuicCrypto> mock;

    @BeforeEach
    void setUp() {
        timeoutHeap = new TimeoutHeap<>(QuicConnection.class);
        selectorMock = mock(SelectorThread.class);
        mock = Mockito.mockStatic(QuicCrypto.class, Answers.CALLS_REAL_METHODS);
        mock.when(() -> QuicCrypto.generateStatelessResetToken(any(byte[].class)))
                .thenReturn(new byte[16]);
    }

    @AfterEach
    void tearDown() {
        if (mock != null) {
            mock.close(); // Crucial to prevent registration on the next test
        }
    }

    @Test
    @DisplayName("Test basic heap insertion and ordering")
    void testBasicHeapInsertion() {
        // Create connections with different timeout values
        QuicConnection conn1 = new QuicConnection(1001L, 
            new InetSocketAddress("127.0.0.1", 5001), new SpscLinkedQueue<>(), selectorMock);
        QuicConnection conn2 = new QuicConnection(1002L, 
            new InetSocketAddress("127.0.0.1", 5002), new SpscLinkedQueue<>(), selectorMock);
        QuicConnection conn3 = new QuicConnection(1003L, 
            new InetSocketAddress("127.0.0.1", 5003), new SpscLinkedQueue<>(), selectorMock);

        conn1.setIdleTimeout(1000); // Will timeout first
        conn2.setIdleTimeout(2000);
        conn3.setIdleTimeout(3000); // Will timeout last

        // Insert in non-sorted order
        timeoutHeap.insertOrUpdate(conn2);
        timeoutHeap.insertOrUpdate(conn3);
        timeoutHeap.insertOrUpdate(conn1);

        // Verify heap size
        assertEquals(3, timeoutHeap.size(), "Heap should contain 3 connections");

        // Verify min-heap property: connection with shortest timeout at top
        QuicConnection top = timeoutHeap.peek();
        assertNotNull(top, "Heap should not be empty");
        assertEquals(1001L, top.getConnectionId(), 
            "Connection with shortest timeout should be at heap top");
    }

    @Test
    @DisplayName("Test heap maintains ordering during poll operations")
    void testHeapOrderingDuringPolling() {
        // Create 5 connections with different timeouts
        QuicConnection[] connections = new QuicConnection[5];
        for (int i = 0; i < 5; i++) {
            connections[i] = new QuicConnection(1001L + i, 
                new InetSocketAddress("127.0.0.1", 5001 + i), new SpscLinkedQueue<>(), selectorMock);
            connections[i].setIdleTimeout((i + 1) * 1000);
            timeoutHeap.insertOrUpdate(connections[i]);
        }

        assertEquals(5, timeoutHeap.size(), "Heap should contain 5 connections");

        // Poll all connections and verify they come out in timeout order
        long previousTimeout = -1;
        for (int i = 0; i < 5; i++) {
            QuicConnection conn = timeoutHeap.poll();
            assertNotNull(conn, "Should poll connection " + i);

            long currentTimeout = conn.getTimeoutTimestamp();
            assertTrue(currentTimeout >= previousTimeout, 
                "Heap should maintain min-heap ordering: timeout " + currentTimeout + 
                " should be >= previous " + previousTimeout);

            previousTimeout = currentTimeout;
        }

        // Verify heap is empty
        assertEquals(0, timeoutHeap.size(), "Heap should be empty after polling all connections");
        assertNull(timeoutHeap.peek(), "Peek should return null on empty heap");
    }

    @Test
    @DisplayName("Test timeout update via insertOrUpdate maintains heap ordering")
    void testTimeoutUpdateMaintainsOrdering() throws InterruptedException {
        // Create 4 connections with same idle timeout but created at different times
        QuicConnection conn1 = new QuicConnection(1001L, new InetSocketAddress("127.0.0.1", 5001), new SpscLinkedQueue<>(), selectorMock);
        conn1.setCurrentTimestamp(50);
        QuicConnection conn2 = new QuicConnection(1002L, new InetSocketAddress("127.0.0.1", 5002), new SpscLinkedQueue<>(), selectorMock);
        conn2.setCurrentTimestamp(100);
        QuicConnection conn3 = new QuicConnection(1003L, new InetSocketAddress("127.0.0.1", 5003), new SpscLinkedQueue<>(), selectorMock);
        conn3.setCurrentTimestamp(150);
        QuicConnection conn4 = new QuicConnection(1004L, new InetSocketAddress("127.0.0.1", 5004), new SpscLinkedQueue<>(), selectorMock);
        conn4.setCurrentTimestamp(200);

        // Set same idle timeout for all
        conn1.setIdleTimeout(1000);
        conn2.setIdleTimeout(1000);
        conn3.setIdleTimeout(1000);
        conn4.setIdleTimeout(1000);

        // Insert all connections
        timeoutHeap.insertOrUpdate(conn1);
        timeoutHeap.insertOrUpdate(conn2);
        timeoutHeap.insertOrUpdate(conn3);
        timeoutHeap.insertOrUpdate(conn4);

        // Verify conn1 is at top (created first, so will timeout first)
        assertEquals(1001L, timeoutHeap.peek().getConnectionId(), 
            "Connection 1001 should be at top initially (oldest)");

        // Update conn1's timeout (simulating packet activity)
        long oldTimeout = conn1.getTimeoutTimestamp();
        conn1.setCurrentTimestamp(200);
        conn1.updateTimeout();
        long newTimeout = conn1.getTimeoutTimestamp();

        assertTrue(newTimeout > oldTimeout, "Timeout should be updated to later time");

        // Re-insert into heap to update position
        timeoutHeap.insertOrUpdate(conn1);

        // Now conn2 should be at top (conn1 was pushed to back due to recent activity)
        QuicConnection top = timeoutHeap.peek();
        assertNotNull(top, "Heap should not be empty");
        assertEquals(1002L, top.getConnectionId(), 
            "Connection 1002 should be at top after conn1 update (conn1 moved to back)");

        // Verify conn1's new timeout is later than conn2's
        assertTrue(conn1.getTimeoutTimestamp() > conn2.getTimeoutTimestamp(),
            "Updated conn1 timeout should be later than conn2 timeout");

        // Verify heap index was updated
        assertTrue(conn1.getTimeoutHeapIndex() >= 0, 
            "Connection should have valid heap index after update");
    }

    @Test
    @DisplayName("Test multiple updates maintain heap invariant")
    void testMultipleUpdatesMaintainInvariant() throws InterruptedException {
        // Create 5 connections
        QuicConnection[] connections = new QuicConnection[5];
        for (int i = 0; i < 5; i++) {
            connections[i] = new QuicConnection(1001L + i, 
                new InetSocketAddress("127.0.0.1", 5001 + i), new SpscLinkedQueue<>(), selectorMock);
            connections[i].setIdleTimeout((i + 1) * 1000);
            timeoutHeap.insertOrUpdate(connections[i]);
        }

        // Update several connections in random order
        Thread.sleep(10);
        connections[4].updateTimeout(); // Conn5: was last, stays last
        timeoutHeap.insertOrUpdate(connections[4]);

        Thread.sleep(10);
        connections[0].updateTimeout(); // Conn1: was first, might move
        timeoutHeap.insertOrUpdate(connections[0]);

        Thread.sleep(10);
        connections[2].updateTimeout(); // Conn3: middle connection
        timeoutHeap.insertOrUpdate(connections[2]);

        // Verify heap still maintains min-heap property
        QuicConnection previous = timeoutHeap.poll();
        assertNotNull(previous, "Should poll first connection");

        while (!timeoutHeap.isEmpty()) {
            QuicConnection current = timeoutHeap.poll();
            assertTrue(current.getTimeoutTimestamp() >= previous.getTimeoutTimestamp(),
                "Heap should maintain ordering after multiple updates");
            previous = current;
        }
    }

    @Test
    @DisplayName("Test connection removal from heap")
    void testConnectionRemoval() {
        QuicConnection conn1 = new QuicConnection(1001L, new InetSocketAddress("127.0.0.1", 5001), new SpscLinkedQueue<>(), selectorMock);
        QuicConnection conn2 = new QuicConnection(1002L, new InetSocketAddress("127.0.0.1", 5002), new SpscLinkedQueue<>(), selectorMock);
        QuicConnection conn3 = new QuicConnection(1003L, new InetSocketAddress("127.0.0.1", 5003), new SpscLinkedQueue<>(), selectorMock);

        conn1.setIdleTimeout(1000);
        conn2.setIdleTimeout(2000);
        conn3.setIdleTimeout(3000);

        timeoutHeap.insertOrUpdate(conn1);
        timeoutHeap.insertOrUpdate(conn2);
        timeoutHeap.insertOrUpdate(conn3);

        assertEquals(3, timeoutHeap.size(), "Heap should have 3 connections");

        // Remove middle connection
        timeoutHeap.remove(conn2);

        assertEquals(2, timeoutHeap.size(), "Heap should have 2 connections after removal");

        // Verify heap still maintains ordering
        assertEquals(1001L, timeoutHeap.poll().getConnectionId(), 
            "Conn1 should be first");
        assertEquals(1003L, timeoutHeap.poll().getConnectionId(), 
            "Conn3 should be second");
    }

    @Test
    @DisplayName("Test connection removed and re-added")
    void testConnectionRemovedAndReAdded() {
        QuicConnection conn = new QuicConnection(1001L, new InetSocketAddress("127.0.0.1", 5001), new SpscLinkedQueue<>(), selectorMock);
        conn.setIdleTimeout(1000);

        // Add
        timeoutHeap.insertOrUpdate(conn);
        assertEquals(1, timeoutHeap.size(), "Heap should have 1 connection");

        // Remove
        timeoutHeap.remove(conn);
        assertEquals(0, timeoutHeap.size(), "Heap should be empty after removal");

        // Update timeout and re-add
        conn.setIdleTimeout(2000);
        timeoutHeap.insertOrUpdate(conn);

        assertEquals(1, timeoutHeap.size(), "Heap should have 1 connection after re-adding");
        assertEquals(1001L, timeoutHeap.peek().getConnectionId(), 
            "Re-added connection should be accessible");
    }

    @Test
    @DisplayName("Test heap with expired and non-expired connections")
    void testHeapWithExpiredConnections() {
        long baseTime = System.currentTimeMillis();

        QuicConnection conn1 = new QuicConnection(1001L, new InetSocketAddress("127.0.0.1", 5001), new SpscLinkedQueue<>(), selectorMock);
        QuicConnection conn2 = new QuicConnection(1002L, new InetSocketAddress("127.0.0.1", 5002), new SpscLinkedQueue<>(), selectorMock);
        QuicConnection conn3 = new QuicConnection(1003L, new InetSocketAddress("127.0.0.1", 5003), new SpscLinkedQueue<>(), selectorMock);

        conn1.setIdleTimeout(100);  // Will expire soon
        conn2.setIdleTimeout(200);  // Will expire soon
        conn3.setIdleTimeout(5000); // Will not expire

        timeoutHeap.insertOrUpdate(conn1);
        timeoutHeap.insertOrUpdate(conn2);
        timeoutHeap.insertOrUpdate(conn3);

        // Simulate time progression
        long futureTime = baseTime + 250;

        // Poll expired connections
        int expiredCount = 0;
        while (!timeoutHeap.isEmpty() && timeoutHeap.peek().getTimeoutTimestamp() <= futureTime) {
            timeoutHeap.poll();
            expiredCount++;
        }

        assertEquals(2, expiredCount, "Two connections should have expired");
        assertEquals(1, timeoutHeap.size(), "One connection should remain");
        assertEquals(1003L, timeoutHeap.peek().getConnectionId(), 
            "Non-expired connection should remain");
    }

    @Test
    @DisplayName("Test heap index tracking")
    void testHeapIndexTracking() {
        QuicConnection conn1 = new QuicConnection(1001L, new InetSocketAddress("127.0.0.1", 5001), new SpscLinkedQueue<>(), selectorMock);
        QuicConnection conn2 = new QuicConnection(1002L, new InetSocketAddress("127.0.0.1", 5002), new SpscLinkedQueue<>(), selectorMock);

        // Before insertion, index should be -1
        assertEquals(-1, conn1.getTimeoutHeapIndex(), "Index should be -1 before insertion");

        // After insertion, index should be valid
        timeoutHeap.insertOrUpdate(conn1);
        assertTrue(conn1.getTimeoutHeapIndex() >= 0, "Index should be valid after insertion");

        timeoutHeap.insertOrUpdate(conn2);
        assertTrue(conn2.getTimeoutHeapIndex() >= 0, "Index should be valid after insertion");

        // Indexes should be different
        assertNotEquals(conn1.getTimeoutHeapIndex(), conn2.getTimeoutHeapIndex(), 
            "Different connections should have different indexes");

        // After removal, index should be -1
        timeoutHeap.remove(conn1);
        assertEquals(-1, conn1.getTimeoutHeapIndex(), "Index should be -1 after removal");
    }

    @Test
    @DisplayName("Test empty heap operations")
    void testEmptyHeapOperations() {
        assertTrue(timeoutHeap.isEmpty(), "New heap should be empty");
        assertEquals(0, timeoutHeap.size(), "New heap should have size 0");
        assertNull(timeoutHeap.peek(), "Peek on empty heap should return null");
        assertNull(timeoutHeap.poll(), "Poll on empty heap should return null");
    }

    @Test
    @DisplayName("Test single element heap")
    void testSingleElementHeap() {
        QuicConnection conn = new QuicConnection(1001L, new InetSocketAddress("127.0.0.1", 5001), new SpscLinkedQueue<>(), selectorMock);
        conn.setIdleTimeout(1000);

        timeoutHeap.insertOrUpdate(conn);

        assertFalse(timeoutHeap.isEmpty(), "Heap should not be empty");
        assertEquals(1, timeoutHeap.size(), "Heap should have size 1");

        QuicConnection peeked = timeoutHeap.peek();
        assertEquals(1001L, peeked.getConnectionId(), "Peek should return the connection");
        assertEquals(1, timeoutHeap.size(), "Peek should not remove element");

        QuicConnection polled = timeoutHeap.poll();
        assertEquals(1001L, polled.getConnectionId(), "Poll should return the connection");
        assertEquals(0, timeoutHeap.size(), "Poll should remove element");
        assertTrue(timeoutHeap.isEmpty(), "Heap should be empty after poll");
    }
}

