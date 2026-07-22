package org.jquic.quic.streamapi.congestion;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TcpPragueTest {
    private TcpPrague prague;
    private long currentTime;

    @BeforeEach
    void setUp() {
        prague = new TcpPrague();
        currentTime = 1000;
    }

    @Test
    void testInitialGetDelay() {
        // Initially should allow sending some data (CWND is 12000)
        long delay = prague.getDelay(currentTime, 1200, 1, 0, 100, 100, 100,
                                 0, 0, 0, 0, 0, 0, 0, 10000, 0, 0, 0);
        assertEquals(0, delay);
    }

    @Test
    void testSlowStartGrowth() {
        long initialCwnd = prague.getCwnd();
        int window = prague.timeWindowMs();
        
        // Simulate ACK of 10000 bytes over window ms
        prague.getDelay(currentTime, 1200, 1, 0, 100, 100, 100,
                      10000, 0, 10000, 0, 8, 0, 0, 10000, 0, 0, 0);
        
        currentTime += window; // After some time
        prague.getDelay(currentTime, 1200, 1, 0, 100, 100, 100,
                      10000, 0, 10000, 0, 8, 0, 0, 10000, 0, 0, 0);
        
        long newCwnd = prague.getCwnd();
        assertTrue(newCwnd > initialCwnd);
        // initialCwnd=12000, ackRate=10000/window, deltaT=window -> +10000
        assertEquals(22000, newCwnd);
    }

    @Test
    void testLossReduction() {
        // Trigger loss
        prague.getDelay(currentTime, 1200, 1, 0, 100, 100, 100,
                      0, 1000, 0, 1000, 1, currentTime, 0, 10000, 0, 0, 0);
        
        long afterLossCwnd = prague.getCwnd();
        assertEquals(6000, afterLossCwnd, "CWND should be halved on loss");
    }

    @Test
    void testEcnAlphaUpdate() {
        // Initial alpha is 0
        assertEquals(0.0, prague.getAlpha());
        int window = prague.timeWindowMs();

        // ACK 10 packets, 2 marked with CE
        // ceCounter should be at least as large as cePacketsInWindow
        prague.getDelay(currentTime, 1200, 1, 0, 100, 100, 100,
                      12000, 0, 12000, 0, 10, 0, 0, 10000, 0, 2, 2);
        
        double alpha = prague.getAlpha();
        // alpha = (1 - 1/16) * 0 + (1/16) * (2/10) = 0.0625 * 0.2 = 0.0125
        assertEquals(0.0125, alpha, 0.0001);

        // Call again after 10ms - should NOT update alpha
        prague.getDelay(currentTime + 10, 1200, 1, 0, 100, 100, 100,
                      12000, 0, 12000, 0, 10, 0, 0, 10000, 0, 4, 2);
        assertEquals(alpha, prague.getAlpha(), "Alpha should not update before window passes");

        // Call again after window + 10ms - should update alpha
        prague.getDelay(currentTime + window + 10, 1200, 1, 0, 100, 100, 100,
                      12000, 0, 12000, 0, 10, 0, 0, 10000, 0, 6, 2);
        assertTrue(prague.getAlpha() > alpha, "Alpha should update after window passes");
    }

    @Test
    void testEcnCwndReduction() {
        // Increase alpha first to have a non-zero reduction
        // Use a large fraction to see significant reduction
        // 10 packets, 8 marked with CE
        prague.getDelay(currentTime, 1200, 1, 0, 100, 100, 100,
                      12000, 0, 12000, 0, 10, 0, 0, 10000, 0, 8, 8);
        
        double alpha = prague.getAlpha(); // 0.0625 * 0.8 = 0.05
        long cwndBefore = prague.getCwnd(); // 12000
        
        // Reset and do it step by step.
        prague = new TcpPrague();
        currentTime = 1000;
        int window = prague.timeWindowMs();
        
        // 1. Update Alpha and trigger ECN reduction
        // First call initializes lastUpdateTimeMs and lastCeCounterAtLastReaction
        // So we need to call it twice or ensure the first call already allows reaction.
        // Actually, in canSend:
        // if (lastUpdateTimeMs == -1) { lastCeCounterAtLastReaction = ceCounter; }
        // if (ceCounter > lastCeCounterAtLastReaction ...)
        // So the first call NEVER triggers ECN reduction if it initializes lastCeCounterAtLastReaction to the current ceCounter.
        
        // Let's call it once to initialize
        prague.getDelay(currentTime, 1200, 1, 0, 100, 100, 100,
                      0, 0, 0, 0, 0, 0, 0, 10000, 0, 0, 0);
        
        // Now call with CE marks, but 0 bytesAckedInWindow to avoid growth for easier calculation
        currentTime += 100; // and enough time for RTT
        prague.getDelay(currentTime, 1200, 1, 0, 100, 100, 100,
                      12000, 0, 0, 0, 10, 0, 0, 10000, 0, 8, 8);
        
        // alpha = 0.05. cwnd reduction = 12000 * 0.05 / 2 = 300. 12000 - 300 = 11700.
        assertEquals(11700, prague.getCwnd());
    }

    @Test
    void testEcnReactionGating() {
        prague = new TcpPrague();
        currentTime = 1000;
        int window = prague.timeWindowMs();
        
        // Initialize
        prague.getDelay(currentTime, 1200, 1, 0, 100, 100, 100,
                      0, 0, 0, 0, 0, 0, 0, 10000, 0, 0, 0);
        
        // 1. First reaction
        currentTime += 100;
        prague.getDelay(currentTime, 1200, 1, 0, 100, 100, 100,
                      12000, 0, 0, 0, 10, 0, 0, 10000, 0, 8, 8);
        long cwndAfter1 = prague.getCwnd();
        assertTrue(cwndAfter1 < 12000);
        
        // 2. Second call after 10ms - should NOT react again even if more CE
        prague.getDelay(currentTime + 10, 1200, 1, 0, 100, 100, 100,
                      12000, 0, 0, 0, 10, 0, 0, 10000, 0, 8, 2);
        assertEquals(cwndAfter1, prague.getCwnd(), "Should not react to ECN again within RTT");
        
        // 3. Third call after 100ms with SAME ceCounter (8) - should NOT react
        currentTime += 110;
        prague.getDelay(currentTime, 1200, 1, 0, 100, 100, 100,
                      12000, 0, 0, 0, 10, 0, 0, 10000, 0, 8, 2);
        assertEquals(cwndAfter1, prague.getCwnd(), "Should not react to ECN if ceCounter didn't increase");
        
        // 4. Fourth call after 100ms with NEW ceCounter (10) - should react
        prague.getDelay(currentTime + 1, 1200, 1, 0, 100, 100, 100,
                      12000, 0, 0, 0, 10, 0, 0, 10000, 0, 10, 2);
        assertTrue(prague.getCwnd() < cwndAfter1, "Should react to new ECN marks after RTT");
    }

    @Test
    void testPacingDelay() {
        // CWND=12000, RTT=100ms. pacingRate = 120 bytes/ms
        prague.getDelay(currentTime, 1200, 1, 0, 100, 100, 100,
                    12000, 0, 12000, 0, 10, 0, 0, 10000, 0, 0, 0);

        // Send a packet
        prague.getDelay(currentTime, 1200, 1, 0, 100, 100, 100,
                    0, 0, 0, 0, 0, 0, 0, 10000, 0, 0, 0);

        // Next packet immediately
        long delay = prague.getDelay(currentTime, 1200, 1, 0, 100, 100, 100,
                                 0, 0, 0, 0, 0, 0, 0, 10000, 0, 0, 0);

        // delay = 1200 / 120 = 10ms = 10,000,000 ns
        assertEquals(10_000_000L, delay);
    }
}
