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
        // Initially in Startup, should allow sending some data (CWND is 38400)
        long delay = bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                                 0, 0, 0, 0, 0, 0, 0, 0, 10000, 0, 0, 0);
        assertEquals(0, delay);
    }

    @Test
    void testCongestionWindowLimit() {
        // Default initial CWND is 38400 bytes
        long inFlight = 37500;
        // Sending 1200 more bytes will exceed 38400
        long delay = bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                                 0, 0, 0, 0, 0, 0, 0, inFlight, 10000, 0, 0, 0);
        
        assertTrue(delay > 0, "Should return delay when CWND exceeded");
    }

    @Test
    void testBwEstimateAndCwndGrowth() {
        // 1. Establish high BW estimate
        // smoothedRtt = 100ms, bytesAckedInRtt = 20000 bytes
        // BW = 20000 / 100 = 200 bytes/ms
        // CWND = 200 * 100 * 2.89 = 57800
        long delay = bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                                 20000, 0, 20000, 0, 16, 0, 0, 0, 10000, 0, 0, 0);
        assertEquals(0, delay);
        
        // Advance time to allow next send without pacing delay
        currentTime += 100;

        // 2. Check if inFlight < new CWND (57800)
        delay = bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                            20000, 0, 20000, 0, 16, 0, 0, 50000, 10000, 0, 0, 0);
        assertEquals(0, delay, "Should NOT delay as inFlight (50000) < CWND (57800)");
        
        currentTime += 100;
        // 3. Exceed new CWND
        delay = bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                            20000, 0, 20000, 0, 16, 0, 0, 57000, 10000, 0, 0, 0);
        assertTrue(delay > 0, "Should delay as inFlight (57000 + 1200) > CWND (57800)");
    }

    @Test
    void testStartupToDrainTransition() {
        // 1. Established BW in Startup
        // BW = 10000 / 100 = 100 bytes/ms. startupMaxBw = 100.
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        
        // 2. Simulate next rounds with no growth (or small growth < 25%)
        // We need 3 rounds of no growth to transition to DRAIN
        for (int i = 0; i < 3; i++) {
            currentTime += 100;
            bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                        11000, 0, 11000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        }

        // State should now be DRAIN. Pacing gain = 1/2.89 = 0.346
        // maxBw = 110. Pacing rate = 110 * 0.346 = 38 bytes/ms
        // CWND = 110 * 100 * 2.89 = 31790
        
        // Let's verify we are in a state that reflects DRAIN (e.g., lower pacing rate)
        // If we exceed CWND, the delay should be based on the DRAIN pacing rate.
        long delay = bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                                 11000, 0, 11000, 0, 8, 0, 0, 32000, 10000, 0, 0, 0);
        
        // excess = 32000 + 1200 - 31790 = 1410
        // delay = 1410 / 38 = 37 ms
        assertTrue(delay >= 30_000_000L, "Delay should be significant in DRAIN due to low pacing gain. Got: " + delay);
    }

    @Test
    void testPacingDelay() {
        // BW = 10000 / 100 = 100 bytes/ms
        // pacingGain = 2.89 (Startup)
        // Pacing rate = 289 bytes/ms = 289,000 bytes/sec
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);

        // Send 1000 bytes. lastSendTimeNs is now.
        bbr.getDelay(0, currentTime, 1000, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);

        // Immediately try to send another 1000 bytes at the SAME time.
        // Expected delay = 1000 bytes / (289 bytes/ms) = 3.46 ms = 3,460,207 ns
        long delay = bbr.getDelay(0, currentTime, 1000, 1, 100, 100, 100,
                                 10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);

        assertTrue(delay >= 3_000_000L, "Should have pacing delay >= 3ms. Got: " + delay);
        assertTrue(delay < 10_000_000L, "Pacing delay should be reasonable < 10ms. Got: " + delay);
    }

    @Test
    void testProbeRttTransition() {
        // 1. Establish initial RTT and BW
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);

        currentTime += 100; // avoid pacing delay

        // Transition to PROBE_BW
        // STARTUP -> DRAIN (needs 3 rounds)
        for (int i = 0; i < 3; i++) {
            currentTime += 100;
            bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                        11000, 0, 11000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        }

        currentTime += 100;

        // DRAIN -> PROBE_BW (needs inFlight <= BDP)
        // maxBw = 110, minRtt = 100. BDP = 11000.
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    11000, 0, 11000, 0, 8, 0, 0, 5000, 10000, 0, 0, 0);

        // 2. Wait 10 seconds for PROBE_RTT
        currentTime += 11000;
        // This call should transition to PROBE_RTT
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    0, 0, 0, 0, 8, 0, 0, 0, 10000, 0, 0, 0);

        // Should now be in PROBE_RTT state, which uses minimum CWND (4800)
        // Let's verify by sending more than 4800 bytes
        // current inFlight is 0. Adding 6000 bytes will exceed 4800.
        long delay = bbr.getDelay(0, currentTime, 6000, 1, 100, 100, 100,
                                 0, 0, 0, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        assertTrue(delay > 0, "Should be blocked by reduced CWND in PROBE_RTT. delay=" + delay);

        // 3. Stay in PROBE_RTT for 200ms
        currentTime += 100;
        delay = bbr.getDelay(0, currentTime, 6000, 1, 100, 100, 100,
                           0, 0, 0, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        assertTrue(delay > 0, "Still in PROBE_RTT after 100ms");

        // 4. Exit PROBE_RTT after 200ms
        currentTime += 150;
        delay = bbr.getDelay(0, currentTime, 6000, 1, 100, 100, 100,
                           0, 0, 0, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        assertEquals(0, delay, "Should have exited PROBE_RTT and restored CWND");
    }

    @Test
    void testProbeBwCycles() {
        // 1. Setup maxBw and minRtt to get into PROBE_BW
        // BW = 100. minRtt = 100. BDP = 10000.
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        
        // STARTUP -> DRAIN
        for (int i = 0; i < 3; i++) {
            currentTime += 100;
            bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                        10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        }
        
        currentTime += 100;
        // 2. DRAIN -> PROBE_BW (DOWN)
        // This call transitions DRAIN -> PROBE_BW because inFlightData <= BDP
        bbr.getDelay(0, currentTime, 1000, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 10000, 10000, 0, 0, 0);
        
        // 3. Verify DOWN phase: pacingGain = 0.9. Rate = 90 bytes/ms.
        // We use inFlightData > BDP to stay in DOWN.
        long delayDown = bbr.getDelay(0, currentTime, 1000, 1, 100, 100, 100,
                                     10000, 0, 10000, 0, 8, 0, 0, 11000, 10000, 0, 0, 0);
        assertEquals(11_111_111L, delayDown, 10000);

        // 4. Transition DOWN -> CRUISE (set inFlight <= BDP)
        currentTime += 100;
        bbr.getDelay(0, currentTime, 1000, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 5000, 10000, 0, 0, 0);
        
        // Verify CRUISE phase: pacingGain = 1.0. Rate = 100 bytes/ms.
        long delayCruise = bbr.getDelay(0, currentTime, 1000, 1, 100, 100, 100,
                                       10000, 0, 10000, 0, 8, 0, 0, 5000, 10000, 0, 0, 0);
        assertEquals(10_000_000L, delayCruise, 10000);

        // 5. Transition CRUISE -> REFILL (after 8 RTTs)
        currentTime += 801; 
        bbr.getDelay(0, currentTime, 1000, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 5000, 10000, 0, 0, 0);
        
        // REFILL pacingGain is also 1.0.
        long delayRefill = bbr.getDelay(0, currentTime, 1000, 1, 100, 100, 100,
                                       10000, 0, 10000, 0, 8, 0, 0, 5000, 10000, 0, 0, 0);
        assertEquals(10_000_000L, delayRefill, 10000);

        // 6. Transition REFILL -> UP (after 1 RTT)
        currentTime += 101;
        bbr.getDelay(0, currentTime, 1000, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 5000, 10000, 0, 0, 0);
        
        // UP pacingGain = 1.25. Rate = 125.
        long delayUp = bbr.getDelay(0, currentTime, 1000, 1, 100, 100, 100,
                                   10000, 0, 10000, 0, 8, 0, 0, 5000, 10000, 0, 0, 0);
        assertEquals(8_000_000L, delayUp, 10000);

        // 7. Transition UP -> DOWN (after inFlight >= 1.25 * BDP)
        currentTime += 100;
        bbr.getDelay(0, currentTime, 1000, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 13000, 10000, 0, 0, 0);
        
        // Back to DOWN. pacingGain = 0.9.
        long delayDownFinal = bbr.getDelay(0, currentTime, 1000, 1, 100, 100, 100,
                                          10000, 0, 10000, 0, 8, 0, 0, 13000, 10000, 0, 0, 0);
        assertEquals(11_111_111L, delayDownFinal, 10000);
    }

    @Test
    void testEcnResponse() {
        // 1. Establish BW estimate and enter PROBE_BW
        // BW = 200 bytes/ms. RTT = 100ms. BDP = 20000.
        // targetCwnd = BDP * 2.0 (cwndGain in PROBE_BW) = 40000.
        
        // Advance time and establish initial BW in STARTUP
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    20000, 0, 20000, 0, 16, 0, 0, 0, 10000, 0, 0, 0);

        // STARTUP needs 3 rounds of no growth to transition to DRAIN
        for (int i = 0; i < 3; i++) {
            currentTime += 100;
            bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                        20000, 0, 20000, 0, 16, 0, 0, 0, 10000, 0, 0, 0);
        }
        
        // Transition to PROBE_BW (DOWN) - needs inFlight <= BDP
        currentTime += 100;
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    20000, 0, 20000, 0, 16, 0, 0, 10000, 10000, 0, 0, 0);
        
        long initialCwnd = bbr.getCwnd();
        // targetCwnd is max(40000, 38400) = 40000
        assertTrue(initialCwnd >= 40000);

        // 2. Simulate ECN CE marks
        // 100% marking: 16 CE packets out of 16 acked packets to speed up alpha growth
        // Also ensure currentTime passes lastEcnReactionTimeMs
        currentTime += 100;
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    20000, 0, 20000, 0, 16, 0, 0, 10000, 10000, 0, 16, 16);

        // After first update, alpha = 0.0625 * 1.0 = 0.0625
        // Reduction = cwnd * (alpha / 2) = 40000 * 0.03125 = 1250
        // We do more rounds to ensure the reaction is triggered
        for (int i = 0; i < 20; i++) {
            currentTime += 100;
            bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                        20000, 0, 20000, 0, 16, 0, 0, 10000, 10000, 0, 16 + 16 * (i+2), 16);
        }

        long reducedCwnd = bbr.getCwnd();
        assertTrue(reducedCwnd < initialCwnd, "CWND should be reduced by ECN in PROBE_BW. Got: " + reducedCwnd + " vs " + initialCwnd);
    }

    @Test
    void testBwReduction() {
        // 1. Establish high BW
        // BW = 10000 / 100 = 100 bytes/ms
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        
        // 2. Simulate some time passes and BW drops significantly
        // Even if we report lower bytesAckedInRtt, maxBw should eventually decrease if implemented correctly.
        
        for (int i = 0; i < 20; i++) {
            currentTime += 100;
            // Report low BW: 1000 / 100 = 10 bytes/ms
            bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                        1000, 0, 1000, 0, 1, 0, 0, 0, 20000, 0, 0, 0);
        }
        
        // At maxBw = 10, Startup pacingGain = 2.89, Pacing rate = 28.9 bytes/ms.
        // Sending 1000 bytes should delay ~34.6ms.
        // We set inFlightData (18000) > cwnd (approx 10*100*2.89 = 2890) to trigger CWND delay.
        
        long delay = bbr.getDelay(0, currentTime, 1000, 1, 100, 100, 100,
                                 1000, 0, 1000, 0, 1, 0, 0, 0, 18000, 0, 0, 0);
        
        System.out.println("Delay after BW drop: " + delay + " ns");
        
        // If maxBw dropped to 10, pacingRate = 10 * 2.89 = 28.9. 
        // inFlight(18000) + data(1000) - cwnd(2890) = 16110
        // delay = 16110 / 28.9 = 557 ms. 
        // Max delay is RTT * 1M = 100 * 1M = 100,000,000 ns.
        assertTrue(delay > 50_000_000L, "Fix verification: maxBw should decrease, causing larger delay. Got: " + delay);
    }

    @Test
    void testStartupExitTiming() {
        // 1. Establish initial BW in Startup
        // smoothedRtt = 100ms, bytesAckedInRtt = 10000 bytes.
        // currentBw = 100 bytes/ms.
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        
        // 2. Simulate sending multiple packets within the SAME RTT with no BW growth
        // We'll call it 5 times at the same currentTime.
        
        for (int i = 0; i < 5; i++) {
            long delay = bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                                     10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
            
            // If it exits STARTUP, the pacing delay for 1200 bytes will jump from ~4ms to ~34ms.
            // We expect it to STAY in STARTUP because 3 RTTs haven't passed.
            assertTrue(delay < 10_000_000L, "Should still be in STARTUP at iteration " + i + ". delay=" + delay);
        }
    }

    @Test
    void testLossResponse() {
        // 1. Establish initial state in PROBE_BW to allow CWND reduction below INITIAL_CWND
        // BW = 200. minRtt = 100. BDP = 20000. cwndGain = 2.0 (PROBE_BW). targetCwnd = 40000.
        
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    20000, 0, 20000, 0, 16, 0, 0, 0, 10000, 0, 0, 0);
        
        // Transition to DRAIN then PROBE_BW
        for (int i = 0; i < 3; i++) {
            currentTime += 100;
            bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                        20000, 0, 20000, 0, 16, 0, 0, 0, 10000, 0, 0, 0);
        }
        currentTime += 100;
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    20000, 0, 20000, 0, 16, 0, 0, 10000, 10000, 0, 0, 0);

        long initialCwnd = bbr.getCwnd();
        assertTrue(initialCwnd >= 40000, "Initial CWND in PROBE_BW should be at least 40000. Got: " + initialCwnd);

        // 2. Trigger loss
        currentTime += 100;
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    20000, 0, 20000, 5000, 8, currentTime, 0, 10000, 10000, 0, 0, 0);
        
        long cwndAfterLoss = bbr.getCwnd();
        assertTrue(cwndAfterLoss < initialCwnd, "CWND should decrease after loss. Got: " + cwndAfterLoss);
        assertEquals((long)(initialCwnd * 0.7), cwndAfterLoss, 100, "CWND should be reduced by ~30%");

        // 3. Verify CWND remains bounded during recovery even if BW grows
        currentTime += 50;
        // Reporting higher BW: 40000 / 100 = 400 bytes/ms. targetCwnd would be 400 * 100 * 2.0 = 80000.
        // But lossEpochStartTime is still set (100ms interval not yet passed).
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    40000, 0, 40000, 5000, 8, currentTime, 0, 10000, 10000, 0, 0, 0);
        
        long cwndDuringRecovery = bbr.getCwnd();
        assertEquals((long)(80000 * 0.7), cwndDuringRecovery, 1000, "CWND should be 0.7 * targetCwnd during recovery");
    }

    @Test
    void testLossResponseIndependence() {
        // 1. Establish high BW
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                20000, 0, 20000, 0, 16, 0, 0, 0, 10000, 0, 0, 0);
        for (int i = 0; i < 3; i++) {
            currentTime += 100;
            bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    20000, 0, 20000, 0, 16, 0, 0, 0, 10000, 0, 0, 0);
        }
        currentTime += 100;
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                20000, 0, 20000, 0, 16, 0, 0, 10000, 10000, 0, 0, 0);

        long initialCwnd = bbr.getCwnd();

        // 2. Trigger loss
        currentTime += 100;
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                20000, 1000, 20000, 1000, 8, currentTime, 0, 10000, 10000, 0, 0, 0);

        long cwndAfterLoss = bbr.getCwnd();
        assertTrue(cwndAfterLoss < initialCwnd);

        // 3. Immediately show that even if BW is very high, CWND is NOT stuck anymore
        // Suppose BW jumped to 1000 bytes/ms. BDP = 100000. targetCwnd = 200000.
        // Even with loss recent, it should be 0.7 * 200000 = 140000.
        currentTime += 10;
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                100000, 0, 100000, 1000, 8, currentTime - 90, 0, 10000, 10000, 0, 0, 0);

        long cwndNew = bbr.getCwnd();
        System.out.println("CWND after BW jump: " + cwndNew);
        assertTrue(cwndNew > cwndAfterLoss, "CWND should grow with BW even if losses were recent");
        assertEquals(140000, cwndNew, 1000);
    }

    @Test
    void testExtraAcked() {
        // 1. Establish initial state
        // BW = 100. minRtt = 100. BDP = 10000. cwndGain = 2.89.
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    10000, 0, 10000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        
        long cwndBefore = bbr.getCwnd();

        // 2. Simulate ACK aggregation (large bytesAckedInWindow jump)
        // BBRv3 tracks maxExtraAcked over 10 RTTs.
        // Current bytesAckedInWindow = 10000.
        // Jump to 30000 in one go.
        currentTime += 100;
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    10000, 0, 30000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        
        // extraAcked becomes 20000.
        // maxExtraAcked is updated when 10 RTTs pass.
        currentTime += 1000;
        bbr.getDelay(0, currentTime, 1200, 1, 100, 100, 100,
                    10000, 0, 40000, 0, 8, 0, 0, 0, 10000, 0, 0, 0);
        
        long cwndAfter = bbr.getCwnd();
        assertTrue(cwndAfter > cwndBefore, "CWND should increase due to extraAcked from ACK aggregation. Before: " + cwndBefore + ", After: " + cwndAfter);
        // BDP = 10000. Gain = 2.89. extra = 20000. Total = 28900 + 20000 = 48900.
        assertTrue(cwndAfter >= 48900, "CWND should include extraAcked. Got: " + cwndAfter);
    }
}

