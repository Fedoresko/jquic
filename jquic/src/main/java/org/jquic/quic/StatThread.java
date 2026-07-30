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
