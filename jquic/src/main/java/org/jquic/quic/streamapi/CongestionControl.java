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
package org.jquic.quic.streamapi;

import org.jquic.quic.linux.ECT;

public interface CongestionControl {
    /**
     * Make a decision to delay packet sending.
     * currentTimeNanos and currentTimeMs do not relate and may have different 0-points in time
     *
     * @param currentTimeNanos       - current time nanoseconds (could be different time scales with currentTimeMs)
     * @param currentTimeMs          - current time milliseconds (could be different time scales with currentTimeNanos)
     * @param dataSize               - packet size
     * @param connectionId           - connectionId
     * @param smoothedRtt            - EWMA smoothed RTT
     * @param lastRtt                - last packet ACK delay
     * @param minRtt                 - minimal RTT
     * @param bytesAckedInRtt        - number of bytes acknowledged during the last smoothed RTT
     * @param bytesLostInRtt         - number of bytes of timed out packets during the last smoothed RTT
     * @param bytesAckedInWindow     - number of bytes acknowledged during the last time window
     * @param bytesLostInWindow      - number of bytes of timed out packets during the last time window
     * @param packetsAckedInWindow   - number of packets acknowledged during the last time window
     * @param lastLostTimeMs         - time last loss detected in milliseconds
     * @param lastAckedTimeMs        - time last ACK received in milliseconds
     * @param inFlightData           - amount of data sent, not yet acknowledged
     * @param receiveBufferRemaining - amount of free space in receive buffer (buffer capacity minus received data, not yet processed)
     * @param sendBufferSize         - number of bytes queued for sending
     * @param ceCounter              - ECN Congestion Experienced counter
     * @param cePacketsInWindow      - number of CE marked packets in the last time window
     * @return the number of nanoseconds paket should be delayed.
     */
    long getDelay(long currentTimeNanos, long currentTimeMs, long dataSize, long connectionId, long smoothedRtt, long lastRtt, long minRtt,
                  long bytesAckedInRtt, long bytesLostInRtt, long bytesAckedInWindow, long bytesLostInWindow, long packetsAckedInWindow,
                  long lastLostTimeMs, long lastAckedTimeMs, long inFlightData, long receiveBufferRemaining, long sendBufferSize,
                  long ceCounter, long cePacketsInWindow);

    /**
     * Time window to calculate aggregated stats up to 100ms
     * @return size in milliseconds
     */
    int timeWindowMs();

    /**
     * Marking that algorithm implies: ECT(0) is default, ECT(1) for algorithms like TcpPrague
     */
    default ECT getEctMarking() { return ECT.ECT_0; }
}

