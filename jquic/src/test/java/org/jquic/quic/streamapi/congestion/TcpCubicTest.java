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
package org.jquic.quic.streamapi.congestion;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TcpCubicTest {
    private TcpCubic cubic;
    private long currentTime;

    @BeforeEach
    void setUp() {
        cubic = new TcpCubic();
        currentTime = 1000;
    }

    @Test
    void testInitialCanSend() {
        // Initially should allow sending some data (CWND is 12000)
        long delay = cubic.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                                 0, 0, 0, 0, 0, 0, 0, 0, 10000, 0, 0, 0);
        assertEquals(0, delay);
    }

    @Test
    void testCongestionWindowLimit() {
        // Default initial CWND is 12000 bytes
        long inFlight = 11000;
        // Sending 1200 more bytes will exceed 12000
        long delay = cubic.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                                 0, 0, 0, 0, 0, 0, 0, inFlight, 10000, 0, 0, 0);
        
        assertTrue(delay > 0, "Should return delay when CWND exceeded");
    }

    @Test
    void testSlowStartGrowth() {
        // Initially in Slow Start
        long initialCwnd = cubic.getCwnd();
        
        // Simulate ACK of 10000 bytes over 100ms
        // timeWindowNanos is 100ms.
        cubic.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                      10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        
        currentTime += cubic.timeWindowMs(); // After 1 RTT
        cubic.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                      10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        
        long newCwnd = cubic.getCwnd();
        assertTrue(newCwnd > initialCwnd, "CWND should increase in Slow Start. Got: " + newCwnd);
        // With our estimated growth, it should roughly double in one RTT if all bytes acked
        // initialCwnd = 12000. ackRate = 10000/100 = 100 bytes/ms. deltaT = 100ms.
        // estimatedAckedDelta = 100 * 100 = 10000.
        // newCwnd = 12000 + 10000 = 22000.
        assertEquals(22000, newCwnd);
    }

    @Test
    void testLossAndMultiplicativeDecrease() {
        // Increase CWND first
        currentTime += 100;
        cubic.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                      10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        long beforeLossCwnd = cubic.getCwnd();
        
        // Simulate loss
        currentTime += 100;
        cubic.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                      0, 1000, 0, 1000, 1, currentTime, 0, 0, 10000, 0, 0, 0);
        
        long afterLossCwnd = cubic.getCwnd();
        assertEquals((long)(beforeLossCwnd * 0.7), afterLossCwnd, "CWND should be reduced by BETA (0.7)");
        assertEquals(afterLossCwnd, cubic.getSsthresh(), "Ssthresh should be set to new CWND");
    }

    @Test
    void testCubicGrowth() {
        // Trigger loss to enter Congestion Avoidance
        cubic.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                      0, 1000, 0, 1000, 1, currentTime, 0, 0, 10000, 0, 0, 0);
        
        long ssthresh = cubic.getSsthresh();
        
        currentTime += 100;
        // ACK some data to trigger growth
        cubic.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                      10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        
        long cwndAfter100ms = cubic.getCwnd();
        assertTrue(cwndAfter100ms > ssthresh, "CWND should grow in Congestion Avoidance");
        
        // Advance time significantly to see cubic behavior
        currentTime += 2000; // 2 seconds
        cubic.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                      10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        
        long cwndAfter2s = cubic.getCwnd();
        assertTrue(cwndAfter2s > cwndAfter100ms, "CWND should keep growing");
    }
    
    @Test
    void testPacingDelay() {
        // Establish CWND and rate
        cubic.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);

        // Send a packet
        cubic.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);

        // Try to send another packet immediately
        long delay = cubic.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                                 10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);

        assertTrue(delay > 0, "Should have pacing delay for consecutive sends. Got: " + delay);
        
        // CWND=12000, RTT=100ms, pacingRate = 1.25 * 12000 / 100 = 150 bytes/ms
        // delay for 1200 bytes = 1200 / 150 = 8ms = 8,000,000 ns
        assertEquals(8_000_000L, delay);
    }
}

