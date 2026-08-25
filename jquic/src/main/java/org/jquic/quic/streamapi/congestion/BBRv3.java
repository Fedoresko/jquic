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

import org.jquic.quic.linux.ECT;
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
    private final long[] maxBwFilter = new long[10];
    private int maxBwFilterIdx = 0;
    private long lastBwFilterUpdateTimeMs = 0;

    private long minRtt = Long.MAX_VALUE;
    private long minRttTimestamp = 0;

    private double pacingGain = 2.89; // Startup gain
    private double cwndGain = 2.89;

    private long startupBwNotIncreasingCount = 0;
    private long lastStartupRoundMs = 0;

    private static final long INITIAL_CWND = 38400; // 32 packets * 1200 bytes
    private static final long MIN_RTT_PROBE_INTERVAL_MS = 10000; // 10 seconds
    private static final long PROBE_RTT_DURATION_MS = 200; // 200ms
    
    // BBRv3 L4S (ECN) parameters
    private static final double G = 0.0625; // EWMA weight for alpha (1/16)
    private double alpha = 0.0;
    private long lastAlphaUpdateTimeMs = -1;
    private long lastEcnReactionTimeMs = -1;
    private long lastCeCounterAtLastReaction = 0;

    private long probeRttDoneTime = 0;

    // PROBE_BW parameters
    private long cycleStartTimeMs = 0;

    private long cwnd = INITIAL_CWND;
    private long lastSendTimeNs = -1;

    private long prevRoundBw = 0;
    
    private long maxBwInProbe = 0;
    private long extraAcked = 0;
    private long lastExtraAckedTimestamp = 0;
    private long maxExtraAcked = 0;
    private long lastAckedBytes = 0;
    private long lastLostBytes = 0;
    private long lossEpochStartTime = -1;
    private long lastLossRoundTimeMs = 0;
    private boolean lossInRound = false;
    
    // For testing
    public long getCwnd() {
        return cwnd;
    }

    @Override
    public long getDelay(long currentTimeNanos, long currentTimeMs, long dataSize, long connectionId, long smoothedRtt, long lastRtt, long minRtt,
                         long bytesAckedInRtt, long bytesLostInRtt, long bytesAckedInWindow, long bytesLostInWindow, long packetsAckedInWindow,
                         long lastLostTimeMs, long lastAckedTimeMs, long inFlightData, long receiveBufferRemaining, long sendBufferSize,
                         long ceCounter, long cePacketsInWindow) {

        long rtt = smoothedRtt > 0 ? smoothedRtt : 100;

        // 0. Update extraAcked (for CWND bound)
        if (lastAckedBytes > 0 && bytesAckedInWindow > lastAckedBytes) {
            long ackedDelta = bytesAckedInWindow - lastAckedBytes;
            extraAcked += ackedDelta;
        }
        lastAckedBytes = bytesAckedInWindow;

        if (currentTimeMs - lastExtraAckedTimestamp >= rtt * 10) {
            maxExtraAcked = extraAcked;
            extraAcked = 0;
            lastExtraAckedTimestamp = currentTimeMs;
        }

        // 0.1 ECN (L4S) Handling
        if (currentTimeMs - lastAlphaUpdateTimeMs >= rtt) {
            if (packetsAckedInWindow > 0) {
                double fraction = (double) cePacketsInWindow / packetsAckedInWindow;
                alpha = (1.0 - G) * alpha + G * fraction;
                lastAlphaUpdateTimeMs = currentTimeMs;
            } else if (cePacketsInWindow > 0) {
                // If we have marks but no packets acked (shouldn't happen with these params usually, 
                // but just in case), we still want to move alpha.
                alpha = (1.0 - G) * alpha + G;
                lastAlphaUpdateTimeMs = currentTimeMs;
            }
        }

        // 0.2 Loss Response (BBRv3)
        if (bytesLostInWindow > lastLostBytes) {
            lossInRound = true;
            if (lossEpochStartTime == -1) {
                lossEpochStartTime = currentTimeMs;
            }
        }
        
        if (currentTimeMs - lastLossRoundTimeMs >= rtt) {
            if (!lossInRound) {
                lossEpochStartTime = -1;
            }
            lossInRound = false;
            lastLossRoundTimeMs = currentTimeMs;
        }
        lastLostBytes = bytesLostInWindow;

        // 0.3 ECN Reaction
        long ecnReduction = 0;
        if (ceCounter > lastCeCounterAtLastReaction) {
            if (currentTimeMs - lastEcnReactionTimeMs >= rtt) {
                // BBRv3 reduction due to ECN: similar to Prague/DCTCP but integrated into BBR logic
                // We apply a multiplicative decrease to CWND based on alpha.
                double reductionFactor = alpha / 2.0;
                ecnReduction = (long) (cwnd * reductionFactor);
                
                // Ensure at least some reduction if alpha is positive and CWND is large enough
                if (ecnReduction == 0 && alpha > 0.001 && cwnd > 0) {
                    ecnReduction = 1;
                }
                
                if (ecnReduction > 0) {
                    lastEcnReactionTimeMs = currentTimeMs;
                    lastCeCounterAtLastReaction = ceCounter;
                    logger.debug("ECN CE detected on connection {}. Alpha: {}, CWND reduction: {}",
                            connectionId, alpha, ecnReduction);
                } else {
                    lastEcnReactionTimeMs = currentTimeMs;
                    lastCeCounterAtLastReaction = ceCounter;
                }
            }
        }
        
        // 1. Update minRtt
        if (minRtt < this.minRtt) {
            this.minRtt = minRtt;
            this.minRttTimestamp = currentTimeMs;
        } else if (this.minRtt == Long.MAX_VALUE && smoothedRtt > 0) {
            this.minRtt = smoothedRtt;
            this.minRttTimestamp = currentTimeMs;
        }

        // 2. Update Bandwidth Estimate (maxBw)
        long currentBw = 0;
        if (bytesAckedInRtt > 0) {
            currentBw = bytesAckedInRtt / rtt;
        }

        // Update maxBw filter (at most once per RTT)
        if (currentTimeMs - lastBwFilterUpdateTimeMs >= rtt) {
            maxBwFilter[maxBwFilterIdx] = currentBw;
            maxBwFilterIdx = (maxBwFilterIdx + 1) % maxBwFilter.length;
            lastBwFilterUpdateTimeMs = currentTimeMs;

            long mBw = 0;
            for (long bw : maxBwFilter) {
                if (bw > mBw) mBw = bw;
            }
            maxBw = mBw;
        } else {
            if (currentBw > maxBw) {
                maxBw = currentBw;
                maxBwFilter[(maxBwFilterIdx + maxBwFilter.length - 1) % maxBwFilter.length] = currentBw;
            }
        }

        // 3. State Machine
        if (state == State.PROBE_BW && probeBwSubState == ProbeBwSubState.UP) {
            if (currentBw > maxBwInProbe) {
                maxBwInProbe = currentBw;
            }
        }
        updateState(currentTimeMs, rtt, inFlightData);

        // 4. Calculate CWND
        if (state == State.PROBE_RTT) {
            cwnd = 4800; // Minimum CWND (4 packets)
        } else if (maxBw > 0 && this.minRtt != Long.MAX_VALUE) {
            long bdp = maxBw * this.minRtt;
            long targetCwnd = (long) (bdp * cwndGain) + maxExtraAcked;
            if (lossEpochStartTime != -1) {
                // In BBRv3, loss response is more integrated. 
                // We apply a Beta factor (0.7) to the target CWND if losses were recently seen.
                targetCwnd = (long) (targetCwnd * 0.7);
            }
            
            cwnd = targetCwnd - ecnReduction;
        }
        
        // Final sanity checks on CWND
        if (state != State.PROBE_RTT) {
            // During STARTUP, we keep CWND at least at INITIAL_CWND to allow fast ramp-up.
            // In other states, we allow CWND to drop to MIN_CWND (4800) to respond to congestion.
            if (state == State.STARTUP) {
                cwnd = Math.max(cwnd, INITIAL_CWND);
            } else {
                cwnd = Math.max(cwnd, 4800);
            }
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
            logger.debug("CWND limited on connection {}: inFlight={}, dataSize={}, cwnd={}, delay={}ns", connectionId, inFlightData, dataSize, cwnd, delayNs);
        }

        // Pacing check
        if (pacingRate > 0) {
            long currentTimeNs = currentTimeMs * 1_000_000L;
            if (lastSendTimeNs == -1 || lastSendTimeNs < currentTimeNs - 1000_000_000L) {
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

    private void updateState(long now, long rtt, long inFlightData) {
        switch (state) {
            case STARTUP:
                if (lastStartupRoundMs == 0) {
                    lastStartupRoundMs = now;
                }

                if (maxBw >= prevRoundBw * 1.25) {
                    prevRoundBw = maxBw;
                    startupBwNotIncreasingCount = 0;
                    lastStartupRoundMs = now;
                } else if (now - lastStartupRoundMs >= rtt) {
                    startupBwNotIncreasingCount++;
                    lastStartupRoundMs = now;
                }

                if (startupBwNotIncreasingCount >= 3) {
                    state = State.DRAIN;
                    pacingGain = 1.0 / 2.89;
                    cwndGain = 2.89;
                    logger.debug("Exiting STARTUP, entered DRAIN. maxBw: {}", maxBw);
                }
                break;
            case DRAIN:
                // Transition to PROBE_BW when queue is drained (BDP reached)
                long drainBdp = maxBw * (minRtt == Long.MAX_VALUE ? rtt : minRtt);
                if (inFlightData <= drainBdp) {
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
        maxBwInProbe = 0;
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
                    logger.debug("Transition to PROBE_BW (DOWN) at {}, maxBw seen in probe: {}", now, maxBwInProbe);
                    maxBwInProbe = 0;
                }
                break;
        }
    }

    @Override
    public ECT getEctMarking() {
        return ECT.ECT_1; // Use ECT(1) for BBRv3 L4S optimization
    }

    @Override
    public int timeWindowMs() {
        return 32; // Standard 32ms window for L4S stats
    }
}

