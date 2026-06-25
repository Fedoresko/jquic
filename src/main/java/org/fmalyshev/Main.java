package org.fmalyshev;

import org.fmalyshev.http3.Http3Request;
import org.fmalyshev.http3.Http3Response;
import org.fmalyshev.http3.Http3Server;
import org.fmalyshev.quic.KeystoreManager;
import org.fmalyshev.quic.KeystoreManager;
import org.fmalyshev.quic.QuicEngine;
import org.fmalyshev.quic.QuicServerConfig;
import org.fmalyshev.quic.QuicServerConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

/**
 * Main entry point for the QUIC/HTTP3 server application.
 *
 * <p>Starts the QuicEngine (UDP multiplexer + eBPF steering) and an HTTP/3 server
 * with the following test endpoints:
 * <ul>
 *   <li>GET /health  – liveness check, returns 200 OK</li>
 *   <li>GET /hello   – friendly greeting with server timestamp</li>
 *   <li>GET /echo    – echoes connection ID and request path back as JSON</li>
 *   <li>*            – 404 Not Found for any other path</li>
 * </ul>
 */
public class Main {

    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) throws Exception {
        logger.info("Starting QUIC/HTTP3 server...");

        // 1. Boot the QUIC engine (acceptor + selector threads, eBPF map setup)
        QuicEngine.init();

        // 2. Build and start the HTTP/3 server with test request handler
        Http3Server http3Server = new Http3Server(Main::handleRequest);
        http3Server.start();

        // 3. Start the HTTPS/1.1 bootstrap server on TCP 4433
        KeystoreManager keystoreManager = new KeystoreManager(QuicServerConfig.createDefault());
        BootstrapHttpServer bootstrapServer = new BootstrapHttpServer(keystoreManager);
        bootstrapServer.start();

        // 4. Register graceful shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutdown signal received, stopping services...");
            try {
                bootstrapServer.stop();
                http3Server.stop();
                QuicEngine.stop();
                logger.info("Services stopped cleanly.");
            } catch (Exception e) {
                logger.error("Error during shutdown", e);
            }
        }, "shutdown-hook"));

        logger.info("Server is up. Press Ctrl+C to stop.");

        // Keep the main thread alive
        Thread.currentThread().join();
    }

    /**
     * Test request handler that dispatches to individual endpoint methods.
     */
    private static Http3Response handleRequest(Http3Request request) {
        logger.debug("Handling {} {}", request.getMethod(), request.getPath());

        return switch (request.getPath()) {
            case "/health" -> handleHealth(request);
            case "/hello"  -> handleHello(request);
            case "/echo"   -> handleEcho(request);
            default        -> Http3Response.notFound();
        };
    }

    /** GET /health – simple liveness probe */
    private static Http3Response handleHealth(Http3Request request) {
        return Http3Response.ok("OK");
    }

    /** GET /hello – friendly greeting */
    private static Http3Response handleHello(Http3Request request) {
        String body = "Hello from QUIC/HTTP3 server! Server time: " + Instant.now();
        return Http3Response.ok(body);
    }

    /** GET /echo – returns request metadata as JSON */
    private static Http3Response handleEcho(Http3Request request) {
        String json = String.format(
                "{\"connectionId\":%d,\"method\":\"%s\",\"path\":\"%s\",\"timestamp\":\"%s\"}",
                request.getConnectionId(),
                request.getMethod(),
                request.getPath(),
                Instant.now()
        );
        return Http3Response.json(json);
    }
}
