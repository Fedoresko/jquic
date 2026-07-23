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
package org.jquic.http3;

import org.jquic.quic.QuicEngine;
import org.jquic.quic.streamapi.QuicStreamEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Basic HTTP/3 server implementation.
 * Registers with QuicEngine's stream engine to handle HTTP/3 protocol.
 */
public class Http3Server {
    private static final Logger logger = LoggerFactory.getLogger(Http3Server.class);

    private final Http3Protocol protocol;
    private final Http3RequestHandler requestHandler;
    private boolean started = false;


    public static final int H3_NO_ERROR = 0x0100;
    public static final int H3_GENERAL_PROTOCOL_ERROR = 0x0101;
    public static final int H3_INTERNAL_ERROR = 0x0102;
    public static final int H3_STREAM_CREATION_ERROR = 0x0103;
    public static final int H3_CLOSED_CRITICAL_STREAM = 0x0104;
    public static final int H3_FRAME_UNEXPECTED = 0x0105;
    public static final int H3_FRAME_ERROR = 0x0106;
    public static final int H3_EXCESSIVE_LOAD = 0x0107;
    public static final int H3_ID_ERROR = 0x0108;
    public static final int H3_SETTINGS_ERROR = 0x0109;
    public static final int H3_MISSING_SETTINGS = 0x010a;
    public static final int H3_REQUEST_REJECTED = 0x010b;
    public static final int H3_REQUEST_CANCELLED = 0x010c;
    public static final int H3_REQUEST_INCOMPLETE = 0x010d;
    public static final int H3_MESSAGE_ERROR = 0x010e;
    public static final int H3_CONNECT_ERROR = 0x010f;
    public static final int H3_VERSION_FALLBACK = 0x0110;


    /**
     * Creates a new HTTP/3 server with the specified request handler.
     * 
     * @param requestHandler Handler for incoming HTTP/3 requests
     */
    public Http3Server(Http3RequestHandler requestHandler) {
        this.requestHandler = requestHandler;
        this.protocol = new Http3Protocol(requestHandler);
    }

    /**
     * Starts the HTTP/3 server by registering with QuicEngine's stream engine.
     * 
     * @throws IllegalStateException if server is already started or stream engine not available
     */
    public void start() {
        if (started) {
            throw new IllegalStateException("HTTP/3 server already started");
        }

        QuicStreamEngine streamEngine = QuicEngine.getStreamEngine();
        if (streamEngine == null) {
            throw new IllegalStateException("QuicEngine stream engine not initialized");
        }

        streamEngine.registerProtocol(protocol);
        started = true;
        logger.info("HTTP/3 server started and registered with protocol: h3");
    }

    /**
     * Stops the HTTP/3 server by unregistering from QuicEngine's stream engine.
     */
    public void stop() {
        if (!started) {
            return;
        }

        QuicStreamEngine streamEngine = QuicEngine.getStreamEngine();
        streamEngine.unregisterProtocol("h3");

        started = false;
        logger.info("HTTP/3 server stopped");
    }

    /**
     * Checks if the server is started.
     */
    public boolean isStarted() {
        return started;
    }
}

