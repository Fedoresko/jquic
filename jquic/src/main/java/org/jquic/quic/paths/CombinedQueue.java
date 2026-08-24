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

import org.jquic.quic.streamapi.impl.ApplicationData;
import org.jquic.quic.struct.TriStateQueue;

public class CombinedQueue implements FrameSource {
    private final SimpleFrameQueue frameQueue = new SimpleFrameQueue();
    private final SimpleFrameQueue ackQueue = new SimpleFrameQueue();
    private final SimpleFrameQueue retansmitQueue = new SimpleFrameQueue();
    private final ApplicationQueue applicationQueue = new ApplicationQueue();

    private int curQueueIndex = 0;
    private boolean readyToPoll = false;

    public void setReadyToPoll(boolean isApplicationLayerReady) {
        this.readyToPoll = isApplicationLayerReady;
    }

    @Override
    public Frame peek() {
        return lookAt(false);
    }

    @Override
    public Frame poll() {
        return lookAt(true);
    }

    public Frame lookAt(boolean poll) {
        if (!readyToPoll) return null;
        for (int i = 0; i < 4; i++) {
            Frame frame = lookIdx(poll, curQueueIndex);
            if (frame != null) return frame;
            curQueueIndex = (curQueueIndex + 1) % 4;
        }
        return null;
    }

    private Frame lookIdx(boolean poll, int idx) {
        return switch (idx) {
            case 0 -> poll ? frameQueue.poll() : frameQueue.peek();
            case 1 -> poll ? ackQueue.poll() : ackQueue.peek();
            case 2 -> poll ? retansmitQueue.poll() : retansmitQueue.peek();
            case 3 -> poll ? applicationQueue.poll() : applicationQueue.peek();
            default -> throw new IllegalStateException("Unexpected value: " + idx);
        };
    }

    public boolean addFrame(Frame frame) {
        return frameQueue.offer(frame);
    }

    public boolean addAck(Frame frame) {
        return ackQueue.offer(frame);
    }

    public boolean addRetransmit(Frame frame) {
        return retansmitQueue.offer(frame);
    }

    public void addApplication(TriStateQueue<ApplicationData> queue) {
        applicationQueue.offer(queue);
    }

    @Override
    public void restart() {
        curQueueIndex = 0;
    }

    public void clear() {
        frameQueue.clear();
        ackQueue.clear();
        retansmitQueue.clear();
        applicationQueue.clear();
    }
}
