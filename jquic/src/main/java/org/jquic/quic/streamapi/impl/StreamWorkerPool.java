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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages a pool of worker threads that process stream frames and ACKs.
 * Each worker maintains <em>two</em> independent SPSC queues:
 * <ul>
 *   <li>{@code frameQueue} вЂ” incoming stream frames (data path)</li>
 *   <li>{@code ackQueue}   вЂ” received ACKs (flow-control path)</li>
 * </ul>
 * Keeping the queues separate ensures that a burst of incoming frames cannot fill the
 * shared queue and prevent ACK processing. Because ACKs drive flow-control window
 * updates, they must always be drainable regardless of frame queue pressure вЂ” this is
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
    private final ApplicationWorker[] workers;
    private final AtomicBoolean running = new AtomicBoolean(false);

    public StreamWorkerPool(int workerCount) {
        this.workerCount = workerCount;
        this.workers = new ApplicationWorker[workerCount];
    }

    /**
     * Starts all worker threads.
     */
    public void start() {
        if (running.compareAndSet(false, true)) {
            for (int i = 0; i < workerCount; i++) {
                ApplicationWorker worker = new ApplicationWorker("ApplicationWorker-" + i);
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

    public ApplicationWorker getStreamWorker(int index) {
        return workers[index];
    }
}

