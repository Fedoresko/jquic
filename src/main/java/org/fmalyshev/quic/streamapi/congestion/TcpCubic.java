package org.fmalyshev.quic.streamapi.congestion;

import org.fmalyshev.quic.streamapi.CongestionControl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of TCP Cubic congestion control algorithm.
 * Based on RFC 8312.
 */
public class TcpCubic implements CongestionControl {
    private static final Logger logger = LoggerFactory.getLogger(TcpCubic.class);

    private static final long INITIAL_CWND = 12000; // 10 packets * 1200 bytes
    private static final long MIN_CWND = 2400; // 2 packets * 1200 bytes
    private static final long MSS = 1200;
    private static final double C = 0.4;
    private static final double BETA = 0.7; // Cubic multiplicative decrease factor

    private long cwnd = INITIAL_CWND;
    private long ssthresh = Long.MAX_VALUE;
    private long wMax = 0;
    private long lastWMax = 0;

    private long lastLossTimeMs = -1;
    private long epochStartMs = -1;

    private long lastSendTimeNs = -1;
    private long lastUpdateTimeMs = -1;

    @Override
    public long canSend(long currentTimeMs, long dataSize, long connectionId, long streamId, long smoothedRtt, long lastRtt, long minRtt,
                        long bytesAckedInRtt, long bytesLostInRtt, long bytesAckedInWindow, long bytesLostInWindow, long packetsAckedInWindow,
                        long lastLostTimeMs, long inFlightData, long receiveBufferRemaining, long sendBufferSize,
                        long ceCounter, long cePacketsInWindow) {

        if (lastUpdateTimeMs == -1) {
            lastUpdateTimeMs = currentTimeMs;
        }

        // 1. Loss detection and Multiplicative Decrease
        if (currentTimeMs - lastLostTimeMs < smoothedRtt && lastLostTimeMs > this.lastLossTimeMs) {
            this.lastLossTimeMs = lastLostTimeMs;

            // Fast Convergence
            if (cwnd < lastWMax) {
                lastWMax = cwnd;
                wMax = (long) (cwnd * (1.0 + BETA) / 2.0);
            } else {
                lastWMax = cwnd;
                wMax = cwnd;
            }

            cwnd = (long) (cwnd * BETA);
            ssthresh = cwnd;
            epochStartMs = -1; // Reset cubic epoch

            logger.debug("Loss detected on connection {}. CWND reduced to {}, wMax {}, ssthresh {}",
                    connectionId, cwnd, wMax, ssthresh);
        }

        // 2. Window growth
        if (bytesAckedInWindow > 0) {
            long deltaT = currentTimeMs - lastUpdateTimeMs;
            if (deltaT > 0) {
                if (cwnd < ssthresh) {
                    // Slow Start: increase by estimated amount acked since last update
                    double ackRate = (double) bytesAckedInWindow / timeWindowMs();
                    long estimatedAckedDelta = (long) (ackRate * deltaT);
                    cwnd += estimatedAckedDelta;
                } else {
                    // Congestion Avoidance: Cubic
                    if (epochStartMs == -1) {
                        epochStartMs = currentTimeMs;
                        if (wMax < cwnd) {
                            wMax = cwnd;
                        }
                    }

                    double t = (currentTimeMs - epochStartMs) / 1000.0;
                    double K = Math.pow(wMax / (double) MSS * (1.0 - BETA) / C, 1.0 / 3.0);
                    double target = C * Math.pow(t - K, 3) + (wMax / (double) MSS);
                    long cubicCwnd = (long) (target * MSS);

                    if (cubicCwnd > cwnd) {
                        cwnd = cubicCwnd;
                    } else {
                        // Standard AIMD increase as fallback/TCP-friendly
                        long rtt = smoothedRtt > 0 ? smoothedRtt : 100;
                        cwnd += (long) (MSS * (double) deltaT / rtt);
                    }
                }
            }
        }

        lastUpdateTimeMs = currentTimeMs;
        cwnd = Math.max(cwnd, MIN_CWND);

        // 3. Pacing & Delay calculation
        long rtt = smoothedRtt > 0 ? smoothedRtt : 100;
        // Pacing rate: 1.25 * cwnd / RTT (standard QUIC pacing for Cubic)
        double pacingRate = 1.25 * cwnd / rtt; // bytes per ms

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
        return 10; // 10ms
    }

    // Package-private for testing
    long getCwnd() {
        return cwnd;
    }

    long getSsthresh() {
        return ssthresh;
    }
}
