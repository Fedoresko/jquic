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

import java.util.concurrent.locks.LockSupport;

/**
 * Worker thread that processes frame tasks.
 * Only this worker thread accesses its connection map - no synchronization needed.
 */
public abstract class StreamWorker extends Thread {
    private static final Logger logger = LoggerFactory.getLogger(StreamWorker.class);

    private long idleCount = 0;
    protected volatile boolean isParked = true;

    public StreamWorker(String name) {
        super(name);
        setDaemon(false);
    }

    public void shutdown() {
        interrupt();
    }

    @Override
    public void run() {
        logger.info("Stream worker {} started", getName());

        while (!Thread.currentThread().isInterrupted()) {
            try {
                boolean didWork = false;

                // Then process one frame from the frame queue.
                didWork |= doWork();

                if (!didWork) {
                    idleCount++;
                    if (idleCount < 100) {
                        Thread.onSpinWait();
                    } else if (idleCount < 200) {
                        Thread.yield();
                    } else {
                        isParked = true;
                        LockSupport.parkNanos(1_000_000_0L);
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

    protected abstract boolean doWork();
}

