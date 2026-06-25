package org.fmalyshev.quic.streamapi.impl;

import org.fmalyshev.quic.streamapi.StreamFrameListener;
import org.jctools.queues.SpscArrayQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages a pool of worker threads that process stream frames and ACKs.
 * Each worker maintains <em>two</em> independent SPSC queues:
 * <ul>
 *   <li>{@code frameQueue} — incoming stream frames (data path)</li>
 *   <li>{@code ackQueue}   — received ACKs (flow-control path)</li>
 * </ul>
 * Keeping the queues separate ensures that a burst of incoming frames cannot fill the
 * shared queue and prevent ACK processing. Because ACKs drive flow-control window
 * updates, they must always be drainable regardless of frame queue pressure — this is
 * the foundation for correct backpressure.
 *
 * <p>Uses consistent hashing to assign connections to workers without lookups.</p>
 *
 * <p>IMPORTANT - Ownership Transfer Semantics:</p>
 * <ul>
 *   <li>ByteBuffers passed to enqueueFrame/enqueueAck are transferred to the worker thread</li>
 *   <li>Caller must NOT access or reuse the ByteBuffer after enqueuing</li>
 *   <li>Uses SPSC queues for zero-copy handoff between selector and worker threads</li>
 * </ul>
 */
public class StreamWorkerPool {
    private static final Logger logger = LoggerFactory.getLogger(StreamWorkerPool.class);

    private final int workerCount;
    private final StreamWorker[] workers;
    private final AtomicBoolean running = new AtomicBoolean(false);

    public StreamWorkerPool(int workerCount) {
        this.workerCount = workerCount;
        this.workers = new StreamWorker[workerCount];
    }

    /**
     * Starts all worker threads.
     */
    public void start() {
        if (running.compareAndSet(false, true)) {
            for (int i = 0; i < workerCount; i++) {
                StreamWorker worker = new StreamWorker("StreamWorker-" + i);
                workers[i] = worker;
                worker.start();
            }
            logger.info("Started {} stream worker threads", workerCount);
        }
    }

    /**
     * Stops all worker threads gracefully.
     */
    public void shutdown() {
        if (running.compareAndSet(true, false)) {
            logger.info("Shutting down stream worker pool");
            for (StreamWorker worker : workers) {
                if (worker != null) {
                    worker.shutdown();
                }
            }
            for (StreamWorker worker : workers) {
                if (worker != null) {
                    try {
                        worker.join(5000);
                    } catch (InterruptedException e) {
                        logger.warn("Interrupted while waiting for worker to stop", e);
                        Thread.currentThread().interrupt();
                    }
                }
            }
            logger.info("Stream worker pool shut down");
        }
    }

    /**
     * Assigns a connection to a worker using consistent hashing.
     * 
     * @param connectionId Connection ID
     * @param manager StreamManager for this connection
     */
    public void assignConnection(long connectionId, StreamManager manager) {
        int workerIndex = getWorkerIndex(connectionId);
        workers[workerIndex].addConnection(connectionId, manager);
        logger.debug("Assigned connection {} to worker {}", connectionId, workerIndex);
    }

    /**
     * Removes a connection from its assigned worker.
     * 
     * @param connectionId Connection ID to remove
     */
    public void removeConnection(long connectionId) {
        int workerIndex = getWorkerIndex(connectionId);
        workers[workerIndex].removeConnection(connectionId);
        logger.debug("Removed connection {} from worker {}", connectionId, workerIndex);
    }

    /**
     * Returns an array of StreamFrameListener, one per worker.
     * Each listener forwards frames to its worker using the worker's queue.
     * Selector threads can directly call listeners[hash(connectionId) % workerCount].
     */
    public StreamFrameListener[] getListeners() {
        StreamFrameListener[] listeners = new StreamFrameListener[workerCount];
        for (int i = 0; i < workerCount; i++) {
            final StreamWorker worker = workers[i];
            listeners[i] = new StreamFrameListener() {
                @Override
                public void onStreamFrame(long connectionId, StreamFrameProcessor.StreamFrame frame) {
                    worker.enqueueFrame(connectionId, frame);
                }

                @Override
                public void onAckReceived(long connectionId, long streamId, long dataLength) {
                    worker.enqueueAck(connectionId, streamId, dataLength);
                }
            };
        }
        return listeners;
    }

    /**
     * Computes worker index for a connection using consistent hashing.
     */
    private int getWorkerIndex(long connectionId) {
        return (int) ((connectionId & 0x7FFFFFFFL) % workerCount);
    }

    /**
     * Frame task for worker processing.
     */
    public static class FrameTask {
        public final long connectionId;
        StreamFrameProcessor.StreamFrame frameData;

        public FrameTask(long connectionId, StreamFrameProcessor.StreamFrame frameData) {
            this.connectionId = connectionId;
            this.frameData = frameData;
        }
    }

    /**
     * ACK task for worker processing.
     */
    public static class AckTask {
        public final long connectionId;
        public final long streamId;
        public final long dataLength;

        public AckTask(long connectionId, long streamId, long dataLength) {
            this.connectionId = connectionId;
            this.streamId = streamId;
            this.dataLength = dataLength;
        }
    }

    /**
     * Worker thread that processes frame and ACK tasks.
     * Only this worker thread accesses its connection map - no synchronization needed.
     * Uses SPSC queues since consistent hashing ensures single producer (selector thread) per worker.
     *
     * <p>Two separate queues are maintained so that ACK processing (which drives flow-control
     * window updates) is never blocked by a full frame queue. Each queue can be drained
     * independently, which is the foundation for correct backpressure.</p>
     */
    private static class StreamWorker extends Thread {
        private static final int FRAME_QUEUE_CAPACITY = 65536; // Power of 2 for performance
        private static final int ACK_QUEUE_CAPACITY   = 16384; // ACKs are smaller and fewer

        private final Map<Long, StreamManager> connections = new java.util.HashMap<>();
        private final SpscArrayQueue<FrameTask> frameQueue = new SpscArrayQueue<>(FRAME_QUEUE_CAPACITY);
        private final SpscArrayQueue<AckTask>   ackQueue   = new SpscArrayQueue<>(ACK_QUEUE_CAPACITY);
        private final AtomicBoolean running = new AtomicBoolean(true);

        public StreamWorker(String name) {
            super(name);
            setDaemon(false);
        }

        public synchronized void addConnection(long connectionId, StreamManager manager) {
            connections.put(connectionId, manager);
        }

        public synchronized void removeConnection(long connectionId) {
            connections.remove(connectionId);
        }

        /**
         * Enqueues an ACK task for processing.
         * IMPORTANT: This method takes ownership of the unencryptedPayload ByteBuffer.
         * The caller must NOT access or modify the buffer after calling this method.
         * 
         * @param connectionId Connection ID
         */
        public void enqueueAck(long connectionId, long streamId, long dataLength) {
            ackQueue.offer(new AckTask(connectionId, streamId, dataLength));
        }

        /**
         * Enqueues a frame task for processing.
         * IMPORTANT: This method takes ownership of the framePayload ByteBuffer.
         * The caller must NOT access or modify the buffer after calling this method.
         * 
         * @param connectionId Connection ID
         */
        public void enqueueFrame(long connectionId, StreamFrameProcessor.StreamFrame frame) {
            // Rough packet size measurement for speed (frame overhead ~20 bytes)
            int roughPacketSize = frame.size();

            // Check maxData limit before enqueuing
            StreamManager manager;
            synchronized (this) {
                manager = connections.get(connectionId);
            }

            if (manager != null) {
                long totalReceived = manager.getTotalReceivedBytes();
                int maxData = manager.getMaxData();

                if (totalReceived + roughPacketSize > maxData) {
                    // Reject frame - exceeds connection maxData limit
                    logger.warn("Rejecting frame for connection {}: would exceed maxData ({} + {} > {})",
                               connectionId, totalReceived, roughPacketSize, maxData);
                    return;
                }

                // Track received bytes at connection level
                manager.addReceivedBytes(roughPacketSize);
            }

            // Transfer ownership of the ByteBuffer to the worker thread via the queue
            frameQueue.offer(new FrameTask(connectionId, frame));
        }

        public void shutdown() {
            running.set(false);
            interrupt();
        }

        @Override
        public void run() {
            logger.info("Stream worker {} started", getName());

            FrameTask currentFrameTask = null;
            while (running.get()) {
                try {
                    boolean didWork = false;

                    // Drain ACKs first: ACKs carry flow-control window updates and must
                    // not be blocked by a full frame queue (backpressure correctness).
                    AckTask ackTask = ackQueue.poll();
                    if (ackTask != null) {
                        didWork = true;
                        StreamManager manager = connections.get(ackTask.connectionId);
                        if (manager != null) {
                            try {
                                // Process ACK - StreamManager handles flow control updates
                                manager.onAckReceived(ackTask.streamId, ackTask.dataLength);
                            } catch (Exception e) {
                                logger.error("Error processing ACK for connection {}", ackTask.connectionId, e);
                            }
                        } else {
                            logger.warn("No manager for connection {} while processing ACK", ackTask.connectionId);
                        }
                    }

                    // Then process one frame from the frame queue.
                    if (currentFrameTask == null) {
                        currentFrameTask = frameQueue.poll();
                    }
                    if (currentFrameTask != null) {
                        StreamManager manager = connections.get(currentFrameTask.connectionId);
                        if (manager != null) {
                            try {
                                // Process the frame directly - StreamManager handles it
                                if (manager.processFrame(currentFrameTask.frameData)) {
                                    currentFrameTask = null;
                                    didWork = true;
                                }
                            } catch (Exception e) {
                                logger.error("Error processing frame for connection {}", currentFrameTask.connectionId, e);
                            }
                        } else {
                            logger.warn("No manager for connection {} while processing frame", currentFrameTask.connectionId);
                        }
                    }

                    if (!didWork) {
                        // Both queues empty - yield to avoid spinning
                        Thread.yield();
                    }

                } catch (Exception e) {
                    logger.error("Error in worker {} processing loop", getName(), e);
                }
            }

            logger.info("Stream worker {} stopped", getName());
        }
    }
}
