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
package org.jquic.quic.struct;

import org.jquic.quic.paths.ConnectionPathController;
import org.jquic.quic.paths.DatagramToSend;

public class PathPriorityQueue {
    private final TimeoutHeap<ConnectionPathController> heap = new TimeoutHeap<>(ConnectionPathController.class);

    public int getSize() {
        return heap.size();
    }

    /**
     * Return the nearest time in the queue.
     * @return timestamp in nanos.
     */
    public long nextTimestamp() {
        ConnectionPathController peek = heap.peek();
        return (peek == null) ? Long.MAX_VALUE : peek.getNextShedNs();
    }

    public DatagramToSend poll(long currentTimeMs, long currentTimeNs) {
        ConnectionPathController polled = heap.poll();
        if (polled == null) {
            return null;
        }
        DatagramToSend newData = polled.pollOutbound(currentTimeMs, currentTimeNs);
        polled.setTimeoutHeapIndex(-1);
        heap.insertOrUpdate(polled);
        return newData;
    }

    public void add(ConnectionPathController controller) {
        heap.insertOrUpdate(controller);
    }

    public void remove(ConnectionPathController controller) {
        heap.remove(controller);
    }
}
