package org.jquic.quic.streamapi;

public interface CongestionControl {
    /**
     * Make a decision to delay packet sending.
     * @param currentTimeMs - current time milliseconds
     * @param dataSize - packet size
     * @param connectionId - connectionId
     * @param streamId - streamId (for priority-based algorithms)
     * @param smoothedRtt - EWMA smoothed RTT
     * @param lastRtt - last packet ACK delay
     * @param minRtt - minimal RTT
     * @param bytesAckedInRtt - number of bytes acknowledged during the last smoothed RTT
     * @param bytesLostInRtt - number of bytes of timed out packets during the last smoothed RTT
     * @param bytesAckedInWindow - number of bytes acknowledged during the last time window
     * @param bytesLostInWindow - number of bytes of timed out packets during the last time window
     * @param packetsAckedInWindow - number of packets acknowledged during the last time window
     * @param lastLostTimeMs - time last loss detected in milliseconds
     * @param inFlightData - amount of data sent, not yet acknowledged
     * @param receiveBufferRemaining - amount of free space in receive buffer (buffer capacity minus received data, not yet processed)
     * @param sendBufferSize - number of bytes queued for sending
     * @param ceCounter - ECN Congestion Experienced counter
     * @param cePacketsInWindow - number of CE packets in the last time window
     * @return number of nanoseconds paket send should be delayed.
     */
    long canSend(long currentTimeMs, long dataSize, long connectionId, long streamId, long smoothedRtt, long lastRtt, long minRtt,
                 long bytesAckedInRtt, long bytesLostInRtt, long bytesAckedInWindow, long bytesLostInWindow, long packetsAckedInWindow,
                 long lastLostTimeMs, long inFlightData, long receiveBufferRemaining, long sendBufferSize,
                 long ceCounter, long cePacketsInWindow);

    /**
     * Time window to calculate aggregated stats
     * @return size in nanoseconds
     */
    int timeWindowMs();
}
