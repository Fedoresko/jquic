package org.jquic;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;

public class ResourceHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getHttpContext().getPath();
        String requestMethod = exchange.getRequestMethod();
        String body = new String(exchange.getRequestBody().readAllBytes());

        System.out.printf("Request: %s %s %s\n", requestMethod, path, body);
    }
}
