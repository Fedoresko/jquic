package org.fmalyshev;

import com.sun.net.httpserver.*;
import org.fmalyshev.quic.KeystoreManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.time.Instant;
import java.util.Objects;

/**
 * Lightweight HTTP/1.1 bootstrap server bound on TCP port 4433.
 * Exposes a single {@code GET /bootstrap} endpoint that clients can use
 * to discover the QUIC/HTTP3 service parameters before upgrading.
 *
 * <p>Built on top of one-nio's {@link HttpServer} for minimal overhead.
 */
public class BootstrapHttpServer {

    private static final Logger logger = LoggerFactory.getLogger(BootstrapHttpServer.class);

    private static final int PORT = 4433;
    private final SSLContext sslContext;
    private final HttpsServer server;

    public BootstrapHttpServer(KeystoreManager keystoreManager) throws Exception {

        sslContext = buildSslContext(keystoreManager);

        server = HttpsServer.create(new InetSocketAddress(java.net.InetAddress.getByName("127.0.0.1"), PORT), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                try {
                    SSLContext context = getSSLContext();
                    SSLParameters sslParams = context.getDefaultSSLParameters();

                    // Force secure modern protocols
                    sslParams.setProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
                    params.setSSLParameters(sslParams);
                } catch (Exception e) {
                    System.out.println("Failed to configure HTTPS parameters");
                }
            }
        });

        server.createContext("/bootstrap", new RootHandler());
        server.createContext("/hello", new BadHandler());

    }

    public void start() {
        server.setExecutor(null); // Creates a default executor
        System.out.println("HTTPS Server started on port " + PORT);
        server.start();
    }

    public void stop() {
        server.stop(0);
    }

    /**
     * Builds an {@link SSLContext} from the private key and certificate chain
     * already loaded by {@link KeystoreManager}, without requiring any extra files.
     */
    private static SSLContext buildSslContext(KeystoreManager keystoreManager) throws Exception {
        // Build an in-memory PKCS12 KeyStore holding the key + chain
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(
                "server",
                keystoreManager.getPrivateKey(),
                new char[0],
                keystoreManager.getCertificateChain()
        );

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);
        return sslContext;
    }

    static class RootHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!Objects.equals(exchange.getRequestMethod(), "GET")) {
                exchange.sendResponseHeaders(405, 0);
                exchange.close();
                return;
            }

            String body = String.format(
                    "{\"protocol\":\"h3\",\"host\":\"0.0.0.0\",\"port\":%d,\"timestamp\":\"%s\"}",
                    PORT, Instant.now()
            );

            exchange.getResponseHeaders().add("Access-Control-Allow-Origin","*");
            exchange.getResponseHeaders().add("Content-Type","application/json; charset=utf-8");
            exchange.getResponseHeaders().add("Alt-Svc","h3=\":4433\"; ma=86400");


            exchange.sendResponseHeaders(200, body.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body.getBytes());
            }
            exchange.close();
        }
    }

    static class BadHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!Objects.equals(exchange.getRequestMethod(), "GET")) {
                exchange.sendResponseHeaders(405, 0);
                exchange.close();
                return;
            }

            String body = String.format(
                    "U-u-uPS!"
            );

            exchange.getResponseHeaders().add("Access-Control-Allow-Origin","*");
            exchange.getResponseHeaders().add("Content-Type","application/html; charset=utf-8");

            exchange.sendResponseHeaders(401, body.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body.getBytes());
            }
            exchange.close();
        }
    }

}
