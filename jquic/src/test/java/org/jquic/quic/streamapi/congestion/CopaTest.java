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

class CopaTest {
    private Copa copa;
    private long currentTime;

    @BeforeEach
    void setUp() {
        copa = new Copa();
        currentTime = 1000;
    }

    @Test
    void testInitialGetDelay() {
        // Initially should allow sending some data (CWND is 12000)
        long delay = copa.getDelay(currentTime, 1200, 1, 100, 100, 100,
                                 0, 0, 0, 0, 0, 0, 0, 10000, 0, 0, 0);
        assertEquals(0, delay);
    }

    @Test
    void testWindowGrowthWhenLowDelay() {
        // Initialize lastUpdateTimeMs
        copa.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    0, 0, 0, 0, 0, 0, 0, 10000, 0, 0, 0);
        
        long initialCwnd = copa.getCwnd();
        
        // queuing delay = 0 (lastRtt=100, minRtt=100) -> targetCwnd = infinity
        // Simulate ACK of one CWND over 100ms
        currentTime += 100;
        copa.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    12000, 0, 12000, 0, 10, 0, 0, 10000, 0, 0, 0);
        
        long newCwnd = copa.getCwnd();
        assertTrue(newCwnd > initialCwnd, "CWND should grow when queuing delay is zero");
        // Growth should be v/delta packets per RTT. v=1, delta=0.5 -> 2 packets = 2400 bytes.
        assertEquals(initialCwnd + 2400, newCwnd);
    }

    @Test
    void testWindowReductionWhenHighDelay() {
        // Initialize lastUpdateTimeMs
        copa.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    0, 0, 0, 0, 0, 0, 0, 10000, 0, 0, 0);
        
        // Set a high delay: lastRtt = 200, minRtt = 100. delta = 0.5.
        // targetCwnd = MSS * 100 / (0.5 * (200 - 100)) = 1200 * 100 / 50 = 2400 bytes.
        // Current cwnd = 12000. 12000 > 2400, so it should decrease.
        
        long initialCwnd = copa.getCwnd();
        
        // Simulate ACK of one CWND over 100ms
        currentTime += 100;
        copa.getDelay(currentTime, 1200, 1, 100, 200, 100,
                    12000, 0, 12000, 0, 10, 0, 0, 10000, 0, 0, 0);
        
        long newCwnd = copa.getCwnd();
        assertTrue(newCwnd < initialCwnd, "CWND should shrink when queuing delay is high");
        // Decrease should be v * delta packets per RTT. v=1, delta=0.5 -> 0.5 packets = 600 bytes.
        assertEquals(initialCwnd - 600, newCwnd);
    }

    @Test
    void testVelocityDoubling() {
        assertEquals(1, copa.getVelocity());
        
        // Initialize
        copa.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    0, 0, 0, 0, 0, 0, 0, 10000, 0, 0, 0);

        // Keep increasing for 2 "RTTs"
        // RTT 1
        currentTime += 100;
        copa.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    12000, 0, 12000, 0, 10, 0, 0, 10000, 0, 0, 0);
        assertEquals(1, copa.getVelocity(), "Velocity should still be 1 after first update");
        
        // RTT 2 - direction same as RTT 1 (increase)
        long currentCwnd = copa.getCwnd();
        currentTime += 100;
        copa.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    currentCwnd, 0, currentCwnd, 0, 10, 0, 0, 10000, 0, 0, 0);
        
        assertEquals(2, copa.getVelocity(), "Velocity should double after two consistent RTTs");
        
        // RTT 3 - still same direction
        currentCwnd = copa.getCwnd();
        currentTime += 100;
        copa.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    currentCwnd, 0, currentCwnd, 0, 10, 0, 0, 10000, 0, 0, 0);
        assertEquals(4, copa.getVelocity());
    }

    @Test
    void testVelocityReset() {
        // Initialize
        copa.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    0, 0, 0, 0, 0, 0, 0, 10000, 0, 0, 0);

        // RTT 1 - Increase
        currentTime += 100;
        copa.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    12000, 0, 12000, 0, 10, 0, 0, 10000, 0, 0, 0);
        // RTT 2 - Increase
        long currentCwnd = copa.getCwnd();
        currentTime += 100;
        copa.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    currentCwnd, 0, currentCwnd, 0, 10, 0, 0, 10000, 0, 0, 0);
        assertEquals(2, copa.getVelocity());
        
        // RTT 3 - Decrease (trigger high delay)
        currentCwnd = copa.getCwnd();
        currentTime += 100;
        copa.getDelay(currentTime, 1200, 1, 100, 500, 100,
                    currentCwnd, 0, currentCwnd, 0, 10, 0, 0, 10000, 0, 0, 0);
        
        assertEquals(1, copa.getVelocity(), "Velocity should reset when direction changes");
    }

    @Test
    void testPacing() {
        // CWND=12000, RTT=100ms. PacingRate = 1.25 * 12000 / 100 = 150 bytes/ms.
        // 1200 bytes should take 1200 / 150 = 8ms.
        
        // Send first packet
        copa.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    0, 0, 0, 0, 0, 0, 0, 10000, 0, 0, 0);
        
        // Try second packet immediately
        long delay = copa.getDelay(currentTime, 1200, 1, 100, 100, 100,
                                 0, 0, 0, 0, 0, 0, 1200, 10000, 0, 0, 0);
        
        assertEquals(8_000_000L, delay, "Pacing delay should be 8ms (8,000,000 ns)");
    }
}

