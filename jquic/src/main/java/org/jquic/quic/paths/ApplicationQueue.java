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
package org.jquic.quic.paths;

import org.jctools.queues.MpscArrayQueue;
import org.jquic.quic.packets.PacketPhase;
import org.jquic.quic.streamapi.impl.ApplicationData;
import org.jquic.quic.struct.TriStateQueue;

import static org.jquic.quic.QuicProperties.OUTBOUND_APP_QUEUE_SIZE;

public class ApplicationQueue implements FrameSource {
    private final MpscArrayQueue<Entry> applicationQueue = new MpscArrayQueue<>(OUTBOUND_APP_QUEUE_SIZE);

    private static class Entry {
        ApplicationData data;
        TriStateQueue<ApplicationData> queue;
        Entry(ApplicationData data, TriStateQueue<ApplicationData> queue) {
            this.data = data;
            this.queue = queue;
        }
    }

    public void offer(TriStateQueue<ApplicationData> dataQueue) {
        applicationQueue.offer(new Entry(dataQueue.poll(), dataQueue));
    }

    @Override
    public Frame poll() {
        Entry entry = applicationQueue.poll();
        if (entry == null) {
            return null;
        }

        ApplicationData data = entry.data;
        if (data != null) {
            entry.data = entry.queue.poll();
            if (entry.data != null) applicationQueue.offer(entry);
            return new Frame(data.data(), PacketPhase.APPLICATION, true);
        } else {
            return poll();
        }
    }

    @Override
    public boolean isEmpty() {
        return applicationQueue.isEmpty();
    }

    public void clear() {
        applicationQueue.drain(
            a -> a.data.data().release()
        );
    }
}
