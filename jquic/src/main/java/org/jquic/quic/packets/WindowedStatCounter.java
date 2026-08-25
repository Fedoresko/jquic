package org.jquic.quic.packets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

public class WindowedStatCounter {
    private static final Logger log = LoggerFactory.getLogger(WindowedStatCounter.class);
    private static final int K_INITIAL_RTT_MS = 333; // Initial RTT estimate: 333ms

    // Bytes acked during last RTT tracking
    private long bytesAckedInLastRtt = 0;
    private int[] ackWindow;
    private int[] lostWindow;
    private long[] packetWindowCE;
    private long lastTimeIdx = 0;

    private long serverCeCounter = -1;

    long intervalCePacketsThisWindow = 0;
    long bytesAckedThisWindow = 0;
    long packetsAckedThisWindow = 0;
    long bytesLostInWindow = 0;
    long bytesLostInLastRtt = 0;
    // Loss detection
    private long lossTime = 0; // Time at which packet loss detected
    private long ackedTime = 0; // Time at which last packed was acked

    long totalSentBytes = 0;
    long totalAckedBytes = 0;

    // RTT tracking (RFC 9002 Section 5)
    int smoothedRtt = K_INITIAL_RTT_MS;
    private int rttVar = K_INITIAL_RTT_MS / 2;
    private int minRtt = Integer.MAX_VALUE;
    int latestRtt = 0;


    private long timeWindowMs = 32;

    public WindowedStatCounter(int timeWindowMs) {
        setTimeWindowMs(Math.max(timeWindowMs, 32));
    }

    public void setTimeWindowMs(int timeWindowMs) {
        if  (timeWindowMs >= 32 && timeWindowMs <= 100) {
            ackWindow = new int[timeWindowMs];
            lostWindow = new int[timeWindowMs];
            packetWindowCE = new long[timeWindowMs];
            this.timeWindowMs = timeWindowMs;
        }
    }

    public void onAckReceived(long timestampMs, long ceCounter) {
        ackedTime = timestampMs;

        if (serverCeCounter == -1) {
            serverCeCounter = ceCounter;
        }

        clearOldTimeBuckets(timestampMs);
        if (ceCounter > serverCeCounter) {
            long ceDelta = ceCounter - serverCeCounter;
            for (int i = 0; i < ceDelta; i++) {
                packetWindowCE[(int)(timestampMs % timeWindowMs)]++;
                intervalCePacketsThisWindow++;
            }
            serverCeCounter = ceCounter;
        }
    }

    public void updateAckStats(long timestampMs, int newlyAckedBytes, Set<Long> newlyAcked) {
        // Update bytesAckedInLastRtt
        if (newlyAckedBytes > 0) {
            ackWindow[(int)(timestampMs % timeWindowMs)] += newlyAckedBytes;
            bytesAckedThisWindow += newlyAckedBytes;
            bytesAckedInLastRtt += newlyAckedBytes;
            packetsAckedThisWindow += newlyAcked.size();
        }

        totalAckedBytes += newlyAckedBytes;
    }



    /**
     * Updates RTT estimates based on ACK (RFC 9002 Section 5).
     *
     * @param packetSentTime When the acked packet was sent
     * @param ackDelay ACK delay reported by peer (in microseconds)
     */
    public void updateRtt(long timestampMs, long packetSentTime, long ackDelay) {
        latestRtt = (int)(timestampMs - packetSentTime) - (int)(ackDelay / 1000);

        // Update min RTT
        if (latestRtt < minRtt) {
            minRtt = latestRtt;
        }

        // First RTT sample
        if (smoothedRtt == K_INITIAL_RTT_MS) {
            smoothedRtt = latestRtt;
            rttVar = latestRtt / 2;
        } else {
            // EWMA smoothing (RFC 9002 Section 5.3)
            int rttVarSample = Math.abs(smoothedRtt - latestRtt);
            rttVar = (3 * rttVar + rttVarSample) / 4;
            smoothedRtt = (7 * smoothedRtt + latestRtt) / 8;
        }

        log.debug("RTT updated - latest: {}ms, smoothed: {}ms, var: {}ms, min: {}ms",
                latestRtt, smoothedRtt, rttVar, minRtt);
    }

    public void onLostPacket(long timestampMs, int packetSize) {
        lostWindow[(int)(timestampMs % timeWindowMs)] += packetSize;
        bytesLostInWindow += packetSize;
        lossTime = timestampMs;
    }

    public void clearOldTimeBuckets(long timeIndex) {
        if (lastTimeIdx == 0) lastTimeIdx = timeIndex;
        if (lastTimeIdx != timeIndex) {
            for (long i = lastTimeIdx+1; i <= timeIndex; i++) {
                int rttEndIndex = (int)( (timeWindowMs + i - Math.min(smoothedRtt, timeWindowMs)) % timeWindowMs);
                bytesAckedInLastRtt -= ackWindow[rttEndIndex];
                bytesAckedThisWindow -= ackWindow[(int)(i % timeWindowMs)];
                bytesLostInLastRtt -= lostWindow[rttEndIndex];
                bytesLostInWindow -= lostWindow[(int)(i % timeWindowMs)];
                intervalCePacketsThisWindow -= packetWindowCE[(int)(i % timeWindowMs)];
                ackWindow[(int)(i % timeWindowMs)] = 0;
                lostWindow[(int)(i % timeWindowMs)] = 0;
                packetWindowCE[(int)(i % timeWindowMs)] = 0;
            }
            lastTimeIdx = timeIndex;
        }
    }

    public long getIntervalCePackets() {
        return intervalCePacketsThisWindow;
    }

    public long getBytesAcked() {
        return bytesAckedThisWindow;
    }

    public long getPacketsAcked() {
        return packetsAckedThisWindow;
    }

    public long getBytesLost() {
        return bytesLostInWindow;
    }

    public long getBytesLostInLastRtt() {
        return smoothedRtt <= timeWindowMs ? bytesLostInLastRtt : (bytesLostInLastRtt / timeWindowMs) * smoothedRtt;
    }

    public long getBytesAckedInLastRtt() {
        return smoothedRtt <= timeWindowMs ? bytesAckedInLastRtt : (bytesAckedInLastRtt / timeWindowMs) * smoothedRtt;
    }

    public long getLossTime() {
        return lossTime;
    }

    public long totalInFlightBytes() {
        return totalSentBytes - totalAckedBytes;
    }

    public long getPTO() {
        return smoothedRtt + 4L * rttVar;
    }

    public long getSmoothedRtt() {
        return smoothedRtt;
    }

    public long getLatestRtt() {
        return latestRtt;
    }

    public long getMinRtt() {
        return minRtt;
    }

    public long getServerCeCounter() {
        return serverCeCounter;
    }

    public long getLastAckTime() {
        return ackedTime;
    }
}
