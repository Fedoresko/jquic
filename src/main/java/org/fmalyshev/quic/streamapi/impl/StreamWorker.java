package org.fmalyshev.quic.streamapi.impl;

import org.fmalyshev.quic.streamapi.frames.StreamFrame;
import org.jctools.queues.MpscArrayQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.locks.LockSupport;

/**
 * Worker thread that processes frame tasks.
 * Only this worker thread accesses its connection map - no synchronization needed.
 */
public class StreamWorker extends Thread {
    private static final Logger logger = LoggerFactory.getLogger(StreamWorker.class);
    private static final int FRAME_QUEUE_CAPACITY = 65536; // Power of 2 for performance
    private static final int ACK_QUEUE_CAPACITY = 16384; // Power of 2 for performance

    private final MpscArrayQueue<StreamWorkerPool.FrameTask> frameQueue = new MpscArrayQueue<>(FRAME_QUEUE_CAPACITY);
    private final MpscArrayQueue<StreamWorkerPool.AckTask> ackQueue = new MpscArrayQueue<>(ACK_QUEUE_CAPACITY);
    private long idleCount = 0;
    private volatile boolean isParked = true;

    public StreamWorker(String name) {
        super(name);
        setDaemon(false);
    }

    /**
     * Enqueues a frame task for processing.
     * IMPORTANT: This method takes ownership of the framePayload ByteBuffer.
     * The caller must NOT access or modify the buffer after calling this method.
     */
    public void enqueueFrame(StreamManager manager, StreamFrame frame) {
        // Transfer ownership of the ByteBuffer to the worker thread via the queue
        frameQueue.offer(new StreamWorkerPool.FrameTask(manager, frame));

        if (isParked) {
            LockSupport.unpark(this);
        }
    }

    public void enqueueAck(StreamManager manager, long streamId, long ackTotalLength) {
        // Transfer ownership of the ByteBuffer to the worker thread via the queue
        ackQueue.offer(new StreamWorkerPool.AckTask(manager, streamId, ackTotalLength));

        if (isParked) {
            LockSupport.unpark(this);
        }
    }


    public void shutdown() {
        interrupt();
    }

    @Override
    public void run() {
        logger.info("Stream worker {} started", getName());

        StreamWorkerPool.FrameTask currentFrameTask = null;
        while (!Thread.currentThread().isInterrupted()) {
            try {
                boolean didWork = false;

                StreamWorkerPool.AckTask ackTask;
                while ((ackTask = ackQueue.poll()) != null) {
                    ackTask.manager.frameProcessor.processAck(ackTask.sreamId, ackTask.totalAckedLength);
                    didWork = true;
                }

                // Then process one frame from the frame queue.
                if (currentFrameTask == null) {
                    currentFrameTask = frameQueue.poll();
                }
                if (currentFrameTask != null) {
                    try {
                        // Process the frame directly - StreamManager handles it
                        if (currentFrameTask.manager.frameProcessor.processFrame(currentFrameTask.frameData, currentFrameTask.manager)) {
                            currentFrameTask = null;
                            didWork = true;
                        }
                    } catch (Exception e) {
                        logger.error("Error processing frame for connection {}", currentFrameTask.manager.getConnectionId(), e);
                    }
                }

                if (!didWork) {
                    idleCount++;
                    if (idleCount < 100) {
                        Thread.onSpinWait();
                    } else if (idleCount < 110) {
                        Thread.yield();
                    } else {
                        isParked = true;
                        LockSupport.parkNanos(10000);
                        isParked = false;
                    }
                } else {
                    idleCount = 0;
                }

            } catch (Exception e) {
                logger.error("Error in worker {} processing loop", getName(), e);
            }
        }

        logger.info("Stream worker {} stopped", getName());
    }
}
