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

import org.jquic.quic.QuicConnection;
import org.jquic.quic.streamapi.ConnectionStreamManager;
import org.jquic.quic.streamapi.QuicApplicationProtocol;
import org.jquic.quic.streamapi.QuicStreamEngine;
import org.jctools.queues.MessagePassingQueue;
import org.jctools.queues.MpmcArrayQueue;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Internal implementation of QUIC stream engine for connection management.
 * This class is used by SelectorThread to manage QUIC connections and route frames.
 * Uses consistent hashing to route frames to workers without concurrent lookups.
 * All methods in this class are called from selector threads (not worker threads).
 */
public class QuicStreamEngineImpl implements QuicStreamEngine {
    private static final Logger logger = LoggerFactory.getLogger(QuicStreamEngineImpl.class);

    private final StreamWorkerPool workerPool;
    private final int workerCount;
    private final ConcurrentHashMap<String, QuicApplicationProtocol> protocols = new ConcurrentHashMap<>();

    private final MpmcArrayQueue<ByteBuffer> userDataBufferPool = new MpmcArrayQueue<>(1024);

    /**
     * Creates a new QuicStreamEngineInternal.
     * Package-private constructor - only QuicStreamEngine should create this.
     *
     * @param workerCount  Number of worker threads for processing stream events
     */
    public QuicStreamEngineImpl(int workerCount) {
        this.workerCount = workerCount;
        this.workerPool = new StreamWorkerPool(workerCount);
    }

    /**
     * Starts the internal engine (worker pool).
     */
    public void start() {
        workerPool.start();
        logger.info("QuicStreamEngineInternal started");
    }

    /**
     * Stops the internal engine.
     */
    public void shutdown() {
        workerPool.shutdown();
        logger.info("QuicStreamEngineInternal shut down");
    }

    /**
     * Creates a new connection and associates it with a protocol.
     * Called by SelectorThread when a new connection is established.
     *
     * @param connectionId Connection ID
     * @param connection   QuicConnection instance
     * @param protocolName Application protocol name
     */
    public ConnectionStreamManager createConnection(long connectionId, QuicConnection connection, String protocolName, MessagePassingQueue<OutboxRecord> outputQueue) {
        QuicApplicationProtocol protocol = protocols.get(protocolName);
        if (protocol == null) {
            logger.error("Protocol {} not registered", protocolName);
            return null;
        }

        // Create connection handler
        var handler = protocol.getConnectionHandler().apply(connectionId);

        // Register the appropriate worker listener based on consistent hashing
        int workerIndex = getWorkerIndex(connectionId);

        // Create stream manager - always server-side (isServer = true)
        StreamManager manager = new StreamManager(
                connection,
                handler,
                protocol,
                workerPool.getStreamWorker(workerIndex),
                outputQueue
        );

        logger.info("Created connection {} with protocol {} (worker {})", connectionId, protocolName, workerIndex);

        return manager;
    }

    /**
     * Computes worker index for a connection using consistent hashing.
     */
    private int getWorkerIndex(long connectionId) {
        return (int) ((connectionId & 0x7FFFFFFFL) % workerCount);
    }

    /**
     * Removes a connection.
     * Called by SelectorThread when a connection is closed.
     *
     * @param connectionId Connection ID to remove
     * @param errorCode    Optional error code
     * @param reason       Optional reason
     */
    public void removeConnection(long connectionId, @Nullable Long errorCode, @Nullable String reason) {
        // Notify protocols - this runs on selector thread, which is acceptable
        // as it's just a notification callback
        for (QuicApplicationProtocol protocol : protocols.values()) {
            protocol.onConnectionClose(connectionId, errorCode, reason);
        }

        logger.info("Removed connection {}", connectionId);
    }

    @Override
    public void registerProtocol(QuicApplicationProtocol protocol) {
        protocols.put(protocol.getProtocolName(), protocol);
    }

    @Override
    public void unregisterProtocol(String protocolName) {
        protocols.remove(protocolName);
    }

    @Override
    public List<QuicApplicationProtocol> getProtocols() {
        return protocols.values().stream().toList();
    }

    @Override
    public QuicApplicationProtocol getProtocol(String protocolName) {
        return protocols.get(protocolName);
    }
}

