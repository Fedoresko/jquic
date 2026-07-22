package org.jquic.quic.streamapi.congestion;

import org.jquic.quic.streamapi.CongestionControl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of BBRv3 (Bottleneck Bandwidth and Round-trip propagation time) algorithm.
 */
public class BBRv3 implements CongestionControl {
    private static final Logger logger = LoggerFactory.getLogger(BBRv3.class);

    private enum State { STARTUP, DRAIN, PROBE_BW, PROBE_RTT }
    private enum ProbeBwSubState { DOWN, CRUISE, REFILL, UP }

    private State state = State.STARTUP;
    private ProbeBwSubState probeBwSubState = ProbeBwSubState.DOWN;
    private long maxBw = 0; // bytes per ms
    private long minRtt = Long.MAX_VALUE;
    private long minRttTimestamp = 0;

    private double pacingGain = 2.89; // Startup gain
    private double cwndGain = 2.89;

    private long startupMaxBw = 0;
    private long startupBwNotIncreasingCount = 0;

    private static final long INITIAL_CWND = 12000; // 10 packets * 1200 bytes
    private static final long MIN_RTT_PROBE_INTERVAL_MS = 10000; // 10 seconds
    private static final long PROBE_RTT_DURATION_MS = 200; // 200ms
    private long probeRttDoneTime = 0;

    // PROBE_BW parameters
    private long cycleStartTimeMs = 0;

    private long cwnd = INITIAL_CWND;
    private long lastSendTimeNs = -1;

    @Override
    public long canSend(long currentTimeMs, long dataSize, long connectionId, long streamId, long smoothedRtt, long lastRtt, long minRtt,
                        long bytesAckedInRtt, long bytesLostInRtt, long bytesAckedInWindow, long bytesLostInWindow, long packetsAckedInWindow,
                        long lastLostTimeMs, long inFlightData, long receiveBufferRemaining, long sendBufferSize,
                        long ceCounter, long cePacketsInWindow) {

        // 1. Update minRtt
        if (minRtt > 0 && minRtt < this.minRtt) {
            this.minRtt = minRtt;
            this.minRttTimestamp = currentTimeMs;
        } else if (this.minRtt == Long.MAX_VALUE && smoothedRtt > 0) {
            this.minRtt = smoothedRtt;
            this.minRttTimestamp = currentTimeMs;
        }

        // 2. Update Bandwidth Estimate (maxBw)
        long currentBw = 0;
        long rtt = smoothedRtt > 0 ? smoothedRtt : 100;
        if (bytesAckedInRtt > 0) {
            currentBw = bytesAckedInRtt / rtt;
        }
        if (currentBw > maxBw) {
            maxBw = currentBw;
        }

        // 3. State Machine
        updateState(currentTimeMs, currentBw, rtt, inFlightData);

        // 4. Calculate CWND
        if (state == State.PROBE_RTT) {
            cwnd = 4800; // Minimum CWND (4 packets)
        } else if (maxBw > 0 && this.minRtt != Long.MAX_VALUE) {
            cwnd = (long) (maxBw * this.minRtt * cwndGain);
        }
        cwnd = Math.max(cwnd, INITIAL_CWND);
        if (state == State.PROBE_RTT) {
            cwnd = 4800; // Force it again to override Math.max(cwnd, INITIAL_CWND)
        }

        // 5. Decision & Pacing
        double pacingRate = maxBw * pacingGain; // bytes per ms
        long delayNs = 0;

        // CWND check
        if (inFlightData + dataSize > cwnd) {
            if (pacingRate > 0) {
                double neededMs = (double)(inFlightData + dataSize - cwnd) / pacingRate;
                delayNs = (long)(Math.max(1.0, neededMs) * 1_000_000.0);
            } else {
                delayNs = 1_000_000L; // Default 1ms
            }
        }

        // Pacing check
        if (pacingRate > 0) {
            long currentTimeNs = currentTimeMs * 1_000_000L;
            if (lastSendTimeNs == -1) {
                lastSendTimeNs = (long)(currentTimeNs - (dataSize * 1_000_000.0 / pacingRate));
            }
            long nextSendTimeNs = (long)(lastSendTimeNs + (dataSize * 1_000_000.0 / pacingRate));
            long pacingDelayNs = nextSendTimeNs - currentTimeNs;
            if (pacingDelayNs > delayNs) {
                delayNs = pacingDelayNs;
            }
        }

        if (delayNs > 0) {
            long maxDelay = rtt * 1_000_000L;
            return Math.min(delayNs, maxDelay);
        }

        lastSendTimeNs = currentTimeMs * 1_000_000L;
        return 0;
    }

    private void updateState(long now, long currentBw, long rtt, long inFlightData) {
        switch (state) {
            case STARTUP:
                if (currentBw > 0 && currentBw < startupMaxBw * 1.25) {
                    startupBwNotIncreasingCount++;
                } else {
                    startupMaxBw = Math.max(startupMaxBw, currentBw);
                    startupBwNotIncreasingCount = 0;
                }
                
                if (startupBwNotIncreasingCount >= 3) {
                    state = State.DRAIN;
                    pacingGain = 1.0 / 2.89;
                    cwndGain = 2.89;
                }
                break;
            case DRAIN:
                // Transition to PROBE_BW when queue is drained (BDP reached)
                if (inFlightData <= maxBw * minRtt) {
                    enterProbeBw(now);
                }
                break;
            case PROBE_BW:
                if (minRttTimestamp > 0 && now - minRttTimestamp >= MIN_RTT_PROBE_INTERVAL_MS) {
                    state = State.PROBE_RTT;
                    pacingGain = 1.0;
                    probeRttDoneTime = now + PROBE_RTT_DURATION_MS;
                    logger.debug("Entering PROBE_RTT at {}", now);
                } else {
                    updateProbeBwSubState(now, rtt, inFlightData);
                }
                break;
            case PROBE_RTT:
                if (now >= probeRttDoneTime) {
                    minRttTimestamp = now;
                    enterProbeBw(now);
                    logger.debug("Exiting PROBE_RTT at {}", now);
                }
                break;
        }
    }

    private void enterProbeBw(long now) {
        state = State.PROBE_BW;
        cwndGain = 2.0;
        probeBwSubState = ProbeBwSubState.DOWN;
        pacingGain = 0.9;
        cycleStartTimeMs = now;
        logger.debug("Entering PROBE_BW (DOWN) at {}", now);
    }

    private void updateProbeBwSubState(long now, long rtt, long inFlightData) {
        long bdp = maxBw * (minRtt == Long.MAX_VALUE ? rtt : minRtt);
        switch (probeBwSubState) {
            case DOWN:
                if (inFlightData <= bdp) {
                    probeBwSubState = ProbeBwSubState.CRUISE;
                    pacingGain = 1.0;
                    cycleStartTimeMs = now;
                    logger.debug("Transition to PROBE_BW (CRUISE) at {}", now);
                }
                break;
            case CRUISE:
                if (now - cycleStartTimeMs >= 8 * rtt) {
                    probeBwSubState = ProbeBwSubState.REFILL;
                    pacingGain = 1.0;
                    cycleStartTimeMs = now;
                    logger.debug("Transition to PROBE_BW (REFILL) at {}", now);
                }
                break;
            case REFILL:
                if (now - cycleStartTimeMs >= rtt) {
                    probeBwSubState = ProbeBwSubState.UP;
                    pacingGain = 1.25;
                    cycleStartTimeMs = now;
                    logger.debug("Transition to PROBE_BW (UP) at {}", now);
                }
                break;
            case UP:
                if (inFlightData >= 1.25 * bdp) {
                    probeBwSubState = ProbeBwSubState.DOWN;
                    pacingGain = 0.9;
                    cycleStartTimeMs = now;
                    logger.debug("Transition to PROBE_BW (DOWN) at {}", now);
                }
                break;
        }
    }

    @Override
    public int timeWindowMs() {
        return 0; // 0ms
    }
}
