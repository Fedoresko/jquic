/*
 * Copyright 2026 Fedor Malyshev
 *
 * Licensed under the Apache License, Version 2.0 (the "License") ;
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
package org.jquic.quic;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.locks.LockSupport;

public class StatThread extends Thread {
    private final static Logger log = LoggerFactory.getLogger(StatThread.class);

    public StatThread() {
        super("Stat thread");
    }

    @Override
    public void run() {
        while (!Thread.currentThread().isInterrupted()) {
            long totalActiveConnections = 0;
            double sumRetransmitRateEma = 0;
            long sumTickTimeEmaNs = 0;
            int threadCount = QuicEngine.getSelectorThreads().size();

            int[] bufferStats = new int[4];

            for (SelectorThread selectorThread : QuicEngine.getSelectorThreads()) {
                totalActiveConnections += selectorThread.getActiveConnectionCount();
                sumRetransmitRateEma += selectorThread.getRetransmitRateEma();
                sumTickTimeEmaNs += selectorThread.getTickTimeEmaNs();

                int[] tBufferStats = selectorThread.bufferStats();
                for (int i = 0; i < tBufferStats.length; i++) {
                    bufferStats[i] += tBufferStats[i];
                }
            }

            log.info("### Total active connections: {} | AVG Tick Time: {}ns | AVG Retransmit Rate: {}",
                    totalActiveConnections, (sumTickTimeEmaNs/threadCount), sumRetransmitRateEma/threadCount);
            log.info("### Total buffer stats: {} read buffers | {} write buffers.", bufferStats[0], bufferStats[1]);

            LockSupport.parkUntil(System.currentTimeMillis() + 1000);
        }
    }
}
