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
package org.jquic;

import org.jquic.http3.Http3Request;
import org.jquic.http3.Http3Response;
import org.jquic.http3.Http3Server;
import org.jquic.quic.KeystoreManager;
import org.jquic.quic.QuicEngine;
import org.jquic.quic.QuicServerConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.AbstractMap;
import java.util.List;

/**
 * Main entry point for the QUIC/HTTP3 server application.
 *
 * <p>Starts the QuicEngine (UDP multiplexer + eBPF steering) and an HTTP/3 server
 * with the following test endpoints:
 * <ul>
 *   <li>GET /health  вЂ“ liveness check, returns 200 OK</li>
 *   <li>GET /hello   вЂ“ friendly greeting with server timestamp</li>
 *   <li>GET /echo    вЂ“ echoes connection ID and request path back as JSON</li>
 *   <li>*            вЂ“ 404 Not Found for any other path</li>
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
            case "/bootstrap" -> handleBootstrap(request);
            default        -> Http3Response.notFound();
        };
    }

    private static Http3Response handleBootstrap(Http3Request request) {
        return Http3Response.json(
                String.format("{\"protocol\":\"h3\",\"host\":\"0.0.0.0\",\"port\":%d,\"timestamp\":\"%s\"}",
                4433, Instant.now()),
                List.of(
                        new AbstractMap.SimpleEntry<>("access-control-allow-origin","*"),
                        new AbstractMap.SimpleEntry<>("alt-svc","h3=\":4433\"; ma=86400")
                )
        );
    }

    /** GET /health вЂ“ simple liveness probe */
    private static Http3Response handleHealth(Http3Request request) {
        return Http3Response.ok("OK", List.of());
    }

    /** GET /hello вЂ“ friendly greeting */
    private static Http3Response handleHello(Http3Request request) {
        String body = "Hello from QUIC/HTTP3 server! Server time: " + Instant.now();
        return Http3Response.ok(body,
                List.of(
                        new AbstractMap.SimpleEntry<>("access-control-allow-origin","*")
                )
        );
    }

    /** GET /echo вЂ“ returns request metadata as JSON */
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

