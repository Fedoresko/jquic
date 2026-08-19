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
package org.jquic.quic.streamapi.impl;

import org.jquic.quic.streamapi.frames.ProtocolFrame;
import org.jctools.queues.MpscArrayQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.locks.LockSupport;

public class ApplicationWorker extends StreamWorker {
    private static final Logger logger = LoggerFactory.getLogger(ApplicationWorker.class);
    private static final int FRAME_QUEUE_CAPACITY = 65536; // Power of 2 for performance
    private static final int ACK_QUEUE_CAPACITY = 16384; // Power of 2 for performance

    private final MpscArrayQueue<FrameTask> frameQueue = new MpscArrayQueue<>(FRAME_QUEUE_CAPACITY);
    private final MpscArrayQueue<AckTask> ackQueue = new MpscArrayQueue<>(ACK_QUEUE_CAPACITY);
    int parkCounter = 0;

    public ApplicationWorker(String name) {
        super(name);
    }

    /**
     * Enqueues a frame task for processing.
     * IMPORTANT: This method takes ownership of the framePayload ByteBuffer.
     * The caller must NOT access or modify the buffer after calling this method.
     */
    public void enqueueFrame(StreamManager manager, ProtocolFrame frame) {
        // Transfer ownership of the ByteBuffer to the worker thread via the queue
        frameQueue.offer(new FrameTask(manager, frame));

        if (isParked) {
            parkCounter++;
            if (parkCounter > 10) {
                LockSupport.unpark(this);
                parkCounter = 0;
            }
        }
    }

    public void enqueueAck(StreamManager manager, long streamId, long offset, long length) {
        // Transfer ownership of the ByteBuffer to the worker thread via the queue
        ackQueue.offer(new AckTask(manager, streamId, offset, length));

        if (isParked) {
            parkCounter++;
            if (parkCounter > 10) {
                LockSupport.unpark(this);
                parkCounter = 0;
            }
        }
    }

    @Override
    protected boolean doWork() {
        boolean didWork = ackQueue.drain( ackTask -> {
            ackTask.manager.frameProcessor.processAck(ackTask.sreamId, ackTask.offset, ackTask.length);
        }) > 0;

        didWork |= frameQueue.drain(currentFrameTask -> {
            try {
                // Process the frame directly - StreamManager handles it
                currentFrameTask.manager.frameProcessor.processFrame(currentFrameTask.frameData);
            } catch (Exception e) {
                logger.error("Error processing frame for connection {}", currentFrameTask.manager.getConnectionId(), e);
            }
        }) > 0;

        return didWork;
    }

    /**
     * Frame task for worker processing.
     */
    public static class FrameTask {
        public final StreamManager manager;
        ProtocolFrame frameData;

        public FrameTask(StreamManager manager, ProtocolFrame frameData) {
            this.manager = manager;
            this.frameData = frameData;
        }
    }

    public static class AckTask {
        public final StreamManager manager;
        long sreamId;
        long offset;
        long length;

        public AckTask(StreamManager manager, long sreamId, long offset, long length) {
            this.manager = manager;
            this.sreamId = sreamId;
            this.offset = offset;
            this.length = length;
        }
    }
}
