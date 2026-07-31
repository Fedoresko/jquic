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
package org.jquic.quic.struct;

import org.jquic.quic.PacketNumberSpace;
import org.jquic.quic.QuicConnection;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.streamapi.impl.ApplicationData;
import org.jquic.quic.streamapi.impl.FlightControl;
import org.jquic.quic.streamapi.impl.StreamManager;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Timed priority queue to use with individual congestion control for each packet.
 */
public class AppDataPriorityQueue {
    private static class Entry implements TimeoutHeap.Entry {
        public final TriStateQueue<ApplicationData> applicationDataQueue;
        public final ApplicationData applicationData;
        public final long timeToSend;
        private int index = -1;

        private Entry(TriStateQueue<ApplicationData> applicationDataQueue, ApplicationData applicationData, long timeToSend) {
            this.applicationDataQueue = applicationDataQueue;
            this.applicationData = applicationData;
            this.timeToSend = timeToSend;
        }

        @Override
        public int getTimeoutHeapIndex() {
            return index;
        }

        @Override
        public void setTimeoutHeapIndex(int idx) {
            index = idx;
        }

        @Override
        public long getTimeoutTimestamp() {
            return timeToSend;
        }
    }

    private final TimeoutHeap<Entry> heap = new TimeoutHeap<>(Entry.class);

    /**
     * Add a new source of ApplicationData to poll.
     * @param applicationDataQueue - source of data;
     */
    public void add(TriStateQueue<ApplicationData> applicationDataQueue, long currentTimeNs) {
        ApplicationData data = applicationDataQueue.poll();
        long timeToSend = currentTimeNs + getCongestionDelayNanos(data.connection(), data.flightControl(), currentTimeNs, data.streamId(), data.data());
        heap.insertOrUpdate(new Entry(applicationDataQueue, data, timeToSend));
    }

    /**
     * Return the nearest time in the queue.
     * @return timestamp in nanos.
     */
    public long nextTimestamp() {
        Entry peek = heap.peek();
        return (peek == null) ? Long.MAX_VALUE : peek.timeToSend;
    }

    /**
     * Pull a new {@link ApplicationData} from queue
     * @return most close to process ApplicationData or null if nothing left
     */
    public ApplicationData poll(long currentTimeNs) {
        Entry polled = heap.poll();
        if (polled == null) {
            return null;
        }
        ApplicationData newData = polled.applicationDataQueue.poll();
        if (newData != null) {
            long timeToSend = currentTimeNs + getCongestionDelayNanos(newData.connection(), newData.flightControl(), currentTimeNs, newData.streamId(), newData.data());
            heap.insertOrUpdate(new Entry(polled.applicationDataQueue, newData, timeToSend));
        }
        return polled.applicationData;
    }

    private long getCongestionDelayNanos(@NonNull QuicConnection connection, @Nullable FlightControl flightControl, long currentTimeNs, long streamId, PoolBuffer data) {
        if (streamId == StreamManager.SERVICE_DATA || connection.getCongestionControl() == null || flightControl == null) {
            return 0;
        }
        PacketNumberSpace.WindowedStats windowedStats = connection.getApplicationSpace().getWindowedStats();
        return connection.getCongestionControl().getDelay(
                currentTimeNs / 1_000_000,
                data.buf().remaining(),
                connection.getConnectionId(),
                streamId,
                connection.getApplicationSpace().getSmoothedRtt(),
                connection.getApplicationSpace().getLatestRtt(),
                connection.getApplicationSpace().getMinRtt(),
                windowedStats.bytesAckedInLastRtt(),
                windowedStats.bytesLostInLastRtt(),
                windowedStats.bytesAcked(),
                windowedStats.bytesLost(),
                windowedStats.packetsAcked(),
                connection.getApplicationSpace().getLossTime(),
                flightControl.getTotalInFlightBytes(),
                flightControl.getMaxStreamDataCap() - flightControl.getBytesBuffered(),
                0,
                connection.getApplicationSpace().getServerCeCounter(),
                windowedStats.intervalCePackets()
        );
    }

}
