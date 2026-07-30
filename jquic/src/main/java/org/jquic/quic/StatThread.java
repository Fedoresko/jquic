package org.jquic.quic;

import java.util.concurrent.locks.LockSupport;

public class StatThread extends Thread {
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
            };

            System.out.println("### Total active connections: " + totalActiveConnections + " | AVG Tick Time: "
                    + (sumTickTimeEmaNs/threadCount) + "ns | AVG Retransmit Rate: " + sumRetransmitRateEma/threadCount);
            System.out.println("### Total buffer stats: " + bufferStats[0] + " read buffers | " +
                    bufferStats[1] + " write buffers.");

            LockSupport.parkUntil(System.currentTimeMillis() + 1000);
        }
    }
}
