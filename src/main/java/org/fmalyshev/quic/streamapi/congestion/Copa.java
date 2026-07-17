package org.fmalyshev.quic.streamapi.congestion;

import org.fmalyshev.quic.streamapi.CongestionControl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of Copa congestion control algorithm.
 * Based on "Copa: Practical Delay-Based Congestion Control for the Internet".
 */
public class Copa implements CongestionControl {
    private static final Logger logger = LoggerFactory.getLogger(Copa.class);

    private static final long INITIAL_CWND = 12000; // 10 packets * 1200 bytes
    private static final long MIN_CWND = 2400; // 2 packets * 1200 bytes
    private static final long MSS = 1200;
    private static final double DEFAULT_DELTA = 0.5;

    private long cwnd = INITIAL_CWND;
    private double delta = DEFAULT_DELTA;
    private int velocity = 1;
    
    private int lastDirection = 0; // 1 for increase, -1 for decrease
    private long bytesAckedSinceLastVelocityUpdate = 0;
    
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

        // 1. Loss handling (Optional for Copa but good for robustness)
        if (bytesLostInWindow > 0 && lastLostTimeMs > lastUpdateTimeMs) {
            // Copa is delay-based, but we can do a small backoff on loss to be safe
            // However, pure Copa relies on delay. Let's add a mild backoff.
            // cwnd = Math.max(MIN_CWND, (long)(cwnd * 0.9));
        }

        // 2. Window update logic
        if (bytesAckedInWindow > 0 && minRtt > 0 && lastRtt > 0) {
            long deltaT = currentTimeMs - lastUpdateTimeMs;
            if (deltaT > 0) {
                double ackRate = (double) bytesAckedInWindow / timeWindowMs();
                long estimatedAckedDelta = (long) (ackRate * deltaT);

                if (estimatedAckedDelta > 0) {
                    // Using lastRtt as standing RTT for simplicity
                    long queuingDelay = Math.max(0, lastRtt - minRtt);

                    long targetCwnd;
                    if (queuingDelay == 0) {
                        targetCwnd = Long.MAX_VALUE;
                    } else {
                        // target_cwnd = MSS * minRtt / (delta * queuing_delay)
                        targetCwnd = (long) (MSS * (double) minRtt / (delta * queuingDelay));
                    }

                    // Velocity update - every RTT (approximated by bytes acked)
                    bytesAckedSinceLastVelocityUpdate += estimatedAckedDelta;
                    if (bytesAckedSinceLastVelocityUpdate >= cwnd) {
                        int currentDirection = (cwnd <= targetCwnd) ? 1 : -1;
                        if (currentDirection == lastDirection) {
                            velocity = Math.min(velocity * 2, 64);
                        } else {
                            velocity = 1;
                        }
                        lastDirection = currentDirection;
                        bytesAckedSinceLastVelocityUpdate = 0;

                        logger.debug("Copa velocity update on connection {}: velocity={}, direction={}, cwnd={}, targetCwnd={}",
                                connectionId, velocity, lastDirection, cwnd, targetCwnd);
                    }

                    // Window update
                    if (cwnd <= targetCwnd) {
                        // Increase: cwnd += v / (delta * cwnd) packets per ACK
                        // In bytes: cwnd += bytesAcked * v * MSS / (delta * cwnd)
                        double increase = (double) estimatedAckedDelta * velocity * MSS / (delta * cwnd);
                        cwnd += (long) increase;
                    } else {
                        // Decrease: cwnd -= v * delta / cwnd packets per ACK
                        // In bytes: cwnd -= bytesAcked * v * delta * MSS / cwnd
                        double decrease = (double) estimatedAckedDelta * velocity * delta * MSS / cwnd;
                        cwnd -= (long) decrease;
                    }
                }
            }
        }

        lastUpdateTimeMs = currentTimeMs;
        cwnd = Math.max(cwnd, MIN_CWND);

        // 3. Pacing & Delay calculation (copied from TcpCubic as it's standard)
        long rtt = smoothedRtt > 0 ? smoothedRtt : 100;
        // Pacing rate: 1.25 * cwnd / RTT
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
        return 100; // 100ms
    }

    // Package-private for testing
    long getCwnd() {
        return cwnd;
    }

    int getVelocity() {
        return velocity;
    }
    
    void setDelta(double delta) {
        this.delta = delta;
    }
}
