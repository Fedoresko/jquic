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

class BBRv3Test {
    private BBRv3 bbr;
    private long currentTime;

    @BeforeEach
    void setUp() {
        bbr = new BBRv3();
        currentTime = 1000;
    }

    @Test
    void testInitialGetDelay() {
        // Initially in Startup, should allow sending some data (CWND is 12000)
        long delay = bbr.getDelay(currentTime, 1200, 1, 100, 100, 100,
                                 0, 0, 0, 0, 0, 0, 0, 10000, 0, 0, 0);
        assertEquals(0, delay);
    }

    @Test
    void testCongestionWindowLimit() {
        // Default initial CWND is 12000 bytes
        long inFlight = 11000;
        // Sending 1200 more bytes will exceed 12000
        long delay = bbr.getDelay(currentTime, 1200, 1, 100, 100, 100,
                                 0, 0, 0, 0, 0, 0, inFlight, 10000, 0, 0, 0);
        
        assertTrue(delay > 0, "Should return delay when CWND exceeded");
    }

    @Test
    void testBwEstimateAndCwndGrowth() {
        // 1. Establish BW estimate
        // smoothedRtt = 100ms, bytesAckedInRtt = 10000 bytes
        // BW = 10000 / 100 = 100 bytes/ms
        // CWND = 100 * 100 * 2.89 = 28900
        long delay = bbr.getDelay(currentTime, 1200, 1, 100, 100, 100,
                                 10000, 0, 10000, 0, 8, 0, 0, 10000, 0, 0, 0);
        assertEquals(0, delay);
        
        // Advance time to allow next send without pacing delay
        currentTime += 100;

        // 2. Check if inFlight < new CWND (28900)
        delay = bbr.getDelay(currentTime, 1200, 1, 100, 100, 100,
                            10000, 0, 10000, 0, 8, 0, 25000, 10000, 0, 0, 0);
        assertEquals(0, delay, "Should NOT delay as inFlight (25000) < CWND (28900)");
        
        currentTime += 100;
        // 3. Exceed new CWND
        delay = bbr.getDelay(currentTime, 1200, 1, 100, 100, 100,
                            10000, 0, 10000, 0, 8, 0, 28000, 10000, 0, 0, 0);
        assertTrue(delay > 0, "Should delay as inFlight (28000 + 1200) > CWND (28900)");
    }

    @Test
    void testStartupToDrainTransition() {
        // 1. Established BW in Startup
        // BW = 10000 / 100 = 100 bytes/ms. startupMaxBw = 100.
        bbr.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 10000, 0, 0, 0);
        
        // 2. Simulate next rounds with no growth (or small growth < 25%)
        // We need 3 rounds of no growth to transition to DRAIN
        for (int i = 0; i < 3; i++) {
            currentTime += 100;
            bbr.getDelay(currentTime, 1200, 1, 100, 100, 100,
                        11000, 0, 11000, 0, 8, 0, 0, 10000, 0, 0, 0);
        }

        // State should now be DRAIN. Pacing gain = 1/2.89 = 0.346
        // maxBw = 110. Pacing rate = 110 * 0.346 = 38 bytes/ms
        // CWND = 110 * 100 * 2.89 = 31790
        
        // Let's verify we are in a state that reflects DRAIN (e.g., lower pacing rate)
        // If we exceed CWND, the delay should be based on the DRAIN pacing rate.
        long delay = bbr.getDelay(currentTime, 1200, 1, 100, 100, 100,
                                 11000, 0, 11000, 0, 8, 0, 32000, 10000, 0, 0, 0);
        
        // excess = 32000 + 1200 - 31790 = 1410
        // delay = 1410 / 38 = 37 ms
        assertTrue(delay >= 30_000_000L, "Delay should be significant in DRAIN due to low pacing gain. Got: " + delay);
    }

    @Test
    void testPacingDelay() {
        // BW = 10000 / 100 = 100 bytes/ms
        // pacingGain = 2.89 (Startup)
        // Pacing rate = 289 bytes/ms = 289,000 bytes/sec
        bbr.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 10000, 0, 0, 0);

        // Send 1000 bytes. lastSendTimeNs is now.
        bbr.getDelay(currentTime, 1000, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 10000, 0, 0, 0);

        // Immediately try to send another 1000 bytes at the SAME time.
        // Expected delay = 1000 bytes / (289 bytes/ms) = 3.46 ms = 3,460,207 ns
        long delay = bbr.getDelay(currentTime, 1000, 1, 100, 100, 100,
                                 10000, 0, 10000, 0, 8, 0, 0, 10000, 0, 0, 0);

        assertTrue(delay >= 3_000_000L, "Should have pacing delay >= 3ms. Got: " + delay);
        assertTrue(delay < 10_000_000L, "Pacing delay should be reasonable < 10ms. Got: " + delay);
    }

    @Test
    void testProbeRttTransition() {
        // 1. Establish initial RTT and BW
        bbr.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 10000, 0, 0, 0);

        currentTime += 100; // avoid pacing delay

        // Transition to PROBE_BW
        // STARTUP -> DRAIN (needs 3 rounds)
        for (int i = 0; i < 3; i++) {
            currentTime += 100;
            bbr.getDelay(currentTime, 1200, 1, 100, 100, 100,
                        11000, 0, 11000, 0, 8, 0, 0, 10000, 0, 0, 0);
        }

        currentTime += 100;

        // DRAIN -> PROBE_BW (needs inFlight <= BDP)
        // maxBw = 110, minRtt = 100. BDP = 11000.
        bbr.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    11000, 0, 11000, 0, 8, 0, 5000, 10000, 0, 0, 0);

        // 2. Wait 10 seconds for PROBE_RTT
        currentTime += 11000;
        // This call should transition to PROBE_RTT
        bbr.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    0, 0, 0, 0, 8, 0, 0, 10000, 0, 0, 0);

        // Should now be in PROBE_RTT state, which uses minimum CWND (4800)
        // Let's verify by sending more than 4800 bytes
        // current inFlight is 0. Adding 6000 bytes will exceed 4800.
        long delay = bbr.getDelay(currentTime, 6000, 1, 100, 100, 100,
                                 0, 0, 0, 0, 8, 0, 0, 10000, 0, 0, 0);
        assertTrue(delay > 0, "Should be blocked by reduced CWND in PROBE_RTT. delay=" + delay);

        // 3. Stay in PROBE_RTT for 200ms
        currentTime += 100;
        delay = bbr.getDelay(currentTime, 6000, 1, 100, 100, 100,
                           0, 0, 0, 0, 8, 0, 0, 10000, 0, 0, 0);
        assertTrue(delay > 0, "Still in PROBE_RTT after 100ms");

        // 4. Exit PROBE_RTT after 200ms
        currentTime += 150;
        delay = bbr.getDelay(currentTime, 6000, 1, 100, 100, 100,
                           0, 0, 0, 0, 8, 0, 0, 10000, 0, 0, 0);
        assertEquals(0, delay, "Should have exited PROBE_RTT and restored CWND");
    }

    @Test
    void testProbeBwCycles() {
        // 1. Setup maxBw and minRtt to get into PROBE_BW
        // BW = 100. minRtt = 100. BDP = 10000.
        bbr.getDelay(currentTime, 1200, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 10000, 0, 0, 0);
        
        // STARTUP -> DRAIN
        for (int i = 0; i < 3; i++) {
            currentTime += 100;
            bbr.getDelay(currentTime, 1200, 1, 100, 100, 100,
                        10000, 0, 10000, 0, 8, 0, 0, 10000, 0, 0, 0);
        }
        
        currentTime += 100;
        // 2. DRAIN -> PROBE_BW (DOWN)
        // This call transitions DRAIN -> PROBE_BW because inFlightData <= BDP
        bbr.getDelay(currentTime, 1000, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 10000, 10000, 0, 0, 0);
        
        // 3. Verify DOWN phase: pacingGain = 0.9. Rate = 90 bytes/ms.
        // We use inFlightData > BDP to stay in DOWN.
        long delayDown = bbr.getDelay(currentTime, 1000, 1, 100, 100, 100,
                                     10000, 0, 10000, 0, 8, 0, 11000, 10000, 0, 0, 0);
        assertEquals(11_111_111L, delayDown, 10000);

        // 4. Transition DOWN -> CRUISE (set inFlight <= BDP)
        currentTime += 100;
        bbr.getDelay(currentTime, 1000, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 5000, 10000, 0, 0, 0);
        
        // Verify CRUISE phase: pacingGain = 1.0. Rate = 100 bytes/ms.
        long delayCruise = bbr.getDelay(currentTime, 1000, 1, 100, 100, 100,
                                       10000, 0, 10000, 0, 8, 0, 5000, 10000, 0, 0, 0);
        assertEquals(10_000_000L, delayCruise, 10000);

        // 5. Transition CRUISE -> REFILL (after 8 RTTs)
        currentTime += 801; 
        bbr.getDelay(currentTime, 1000, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 5000, 10000, 0, 0, 0);
        
        // REFILL pacingGain is also 1.0.
        long delayRefill = bbr.getDelay(currentTime, 1000, 1, 100, 100, 100,
                                       10000, 0, 10000, 0, 8, 0, 5000, 10000, 0, 0, 0);
        assertEquals(10_000_000L, delayRefill, 10000);

        // 6. Transition REFILL -> UP (after 1 RTT)
        currentTime += 101;
        bbr.getDelay(currentTime, 1000, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 5000, 10000, 0, 0, 0);
        
        // UP pacingGain = 1.25. Rate = 125.
        long delayUp = bbr.getDelay(currentTime, 1000, 1, 100, 100, 100,
                                   10000, 0, 10000, 0, 8, 0, 5000, 10000, 0, 0, 0);
        assertEquals(8_000_000L, delayUp, 10000);

        // 7. Transition UP -> DOWN (after inFlight >= 1.25 * BDP)
        currentTime += 100;
        bbr.getDelay(currentTime, 1000, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 13000, 10000, 0, 0, 0);
        
        // Back to DOWN. pacingGain = 0.9.
        long delayDownFinal = bbr.getDelay(currentTime, 1000, 1, 100, 100, 100,
                                          10000, 0, 10000, 0, 8, 0, 13000, 10000, 0, 0, 0);
        assertEquals(11_111_111L, delayDownFinal, 10000);
    }
}

