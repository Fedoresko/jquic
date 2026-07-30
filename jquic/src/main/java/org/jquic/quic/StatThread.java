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

            for (SelectorThread selectorThread : QuicEngine.getSelectorThreads()) {
                totalActiveConnections += selectorThread.getActiveConnectionCount();
                sumRetransmitRateEma += selectorThread.getRetransmitRateEma();
                sumTickTimeEmaNs += selectorThread.getTickTimeEmaNs();
            };

            System.out.println("### Total active connections: " + totalActiveConnections + " | AVG Tick Time: "
                    + (sumTickTimeEmaNs/threadCount) + "ns | AVG Retransmit Rate: " + sumRetransmitRateEma/threadCount);

            LockSupport.parkUntil(System.currentTimeMillis() + 5000);
        }
    }
}
