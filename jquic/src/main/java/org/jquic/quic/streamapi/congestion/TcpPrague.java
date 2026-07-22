package org.jquic.quic.streamapi.congestion;

import org.jquic.quic.streamapi.CongestionControl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of TCP Prague congestion control algorithm.
 * TCP Prague is designed for L4S (Low Latency, Low Loss, Scalable throughput).
 * It uses Explicit Congestion Notification (ECN) and a fractional response to congestion.
 */
public class TcpPrague implements CongestionControl {
    private static final Logger logger = LoggerFactory.getLogger(TcpPrague.class);

    private static final long INITIAL_CWND = 12000; // 10 packets * 1200 bytes
    private static final long MIN_CWND = 2400; // 2 packets * 1200 bytes
    private static final long MSS = 1200;
    
    // TCP Prague / DCTCP constants
    private static final double G = 0.0625; // EWMA weight for alpha (1/16)
    
    private long cwnd = INITIAL_CWND;
    private long ssthresh = Long.MAX_VALUE;
    
    private double alpha = 0.0; // Fraction of packets marked with CE
    private long lastLossTimeMs = -1;
    private long lastUpdateTimeMs = -1;
    private long lastSendTimeNs = -1;
    
    // Gating for windowed updates
    private long lastAlphaUpdateTimeMs = -1;
    private long lastEcnReactionTimeMs = -1;
    private long lastCeCounterAtLastReaction = 0;

    @Override
    public long getDelay(long currentTimeMs, long dataSize, long connectionId, long streamId, long smoothedRtt, long lastRtt, long minRtt,
                         long bytesAckedInRtt, long bytesLostInRtt, long bytesAckedInWindow, long bytesLostInWindow, long packetsAckedInWindow,
                         long lastLostTimeMs, long inFlightData, long receiveBufferRemaining, long sendBufferSize,
                         long ceCounter, long cePacketsInWindow) {

        if (lastUpdateTimeMs == -1) {
            lastUpdateTimeMs = currentTimeMs;
            lastCeCounterAtLastReaction = ceCounter;
        }

        // 1. Update Alpha (EWMA of fraction of CE-marked packets)
        // Update at most once per window to avoid over-sampling the same window stats
        if (currentTimeMs - lastAlphaUpdateTimeMs >= timeWindowMs()) {
            if (packetsAckedInWindow > 0) {
                double fraction = (double) cePacketsInWindow / packetsAckedInWindow;
                alpha = (1.0 - G) * alpha + G * fraction;
                lastAlphaUpdateTimeMs = currentTimeMs;
            }
        }

        // 2. Handle Loss (Classic Congestion Response)
        if (bytesLostInWindow > 0 && lastLostTimeMs > this.lastLossTimeMs) {
            this.lastLossTimeMs = lastLostTimeMs;
            cwnd = (long) (cwnd * 0.5); // Standard Multiplicative Decrease for loss
            ssthresh = cwnd;
            logger.debug("Loss detected on connection {}. CWND reduced to {}, ssthresh {}", 
                    connectionId, cwnd, ssthresh);
        }

        // 3. Handle ECN (L4S Response)
        // TCP Prague responds to ECN CE marks by reducing CWND by (1 - alpha/2)
        // React at most once per RTT and only if NEW CE marks were received
        long rtt = smoothedRtt > 0 ? smoothedRtt : 100;
        if (ceCounter > lastCeCounterAtLastReaction && currentTimeMs - lastEcnReactionTimeMs >= rtt) {
             long reduction = (long) (cwnd * (alpha / 2.0));
             if (reduction > 0) {
                 cwnd -= reduction;
                 ssthresh = cwnd;
                 lastEcnReactionTimeMs = currentTimeMs;
                 lastCeCounterAtLastReaction = ceCounter;
                 logger.debug("ECN CE detected on connection {}. Alpha: {}, CWND reduced by {} to {}", 
                         connectionId, alpha, reduction, cwnd);
             }
        }

        // 4. Window Growth
        if (bytesAckedInWindow > 0) {
            long deltaT = currentTimeMs - lastUpdateTimeMs;
            if (deltaT > 0) {
                if (cwnd < ssthresh) {
                    // Slow Start
                    double ackRate = (double) bytesAckedInWindow / timeWindowMs();
                    long estimatedAckedDelta = (long) (ackRate * deltaT);
                    cwnd += estimatedAckedDelta;
                } else {
                    // Congestion Avoidance: Scalable growth (1 packet per RTT)
                    cwnd += (long) (MSS * (double) deltaT / rtt);
                }
            }
        }

        lastUpdateTimeMs = currentTimeMs;
        cwnd = Math.max(cwnd, MIN_CWND);

        // 5. Pacing & Delay calculation
        // Pacing is mandatory for Prague. Rate = CWND / RTT
        double pacingRate = (double) cwnd / rtt; // bytes per ms
        
        long delayNs = 0;

        // CWND check
        if (inFlightData + dataSize > cwnd) {
            if (pacingRate > 0) {
                double neededMs = (double) (inFlightData + dataSize - cwnd) / pacingRate;
                delayNs = (long) (Math.max(1.0, neededMs) * 1_000_000.0);
            } else {
                delayNs = 1_000_000L;
            }
        }

        // Pacing check
        if (pacingRate > 0) {
            long currentTimeNs = currentTimeMs * 1_000_000L;
            if (lastSendTimeNs == -1) {
                lastSendTimeNs = (long) (currentTimeNs - (dataSize * 1_000_000.0 / pacingRate));
            }
            long nextSendTimeNs = (long) (lastSendTimeNs + (dataSize * 1_000_000.0 / pacingRate));
            long pacingDelayNs = nextSendTimeNs - currentTimeNs;
            if (pacingDelayNs > delayNs) {
                delayNs = pacingDelayNs;
            }
        }

        if (delayNs > 0) {
            long maxDelay = (smoothedRtt > 0 ? smoothedRtt : 1000L) * 1_000_000L;
            return Math.min(delayNs, maxDelay);
        }

        lastSendTimeNs = currentTimeMs * 1_000_000L;
        return 0;
    }

    @Override
    public int timeWindowMs() {
        return 32; // 32ms
    }

    // For testing
    long getCwnd() {
        return cwnd;
    }

    double getAlpha() {
        return alpha;
    }
}
