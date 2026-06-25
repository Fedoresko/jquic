package org.fmalyshev.http3;

import org.fmalyshev.quic.QuicEngine;
import org.fmalyshev.quic.streamapi.QuicStreamEngine;
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
        if (streamEngine != null) {
            streamEngine.unregisterProtocol("h3");
        }

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
