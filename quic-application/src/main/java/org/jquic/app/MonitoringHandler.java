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
package org.jquic.app;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.jquic.quic.QuicProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MonitoringHandler implements HttpHandler {
    private static final Logger logger =  LoggerFactory.getLogger(MonitoringHandler.class);

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        logger.warn("MonitoringHandler is handling {}", exchange.getRequestURI());

        String path = exchange.getRequestURI().getPath();

        // Context is registered at /monitoring
        // We want to handle /monitoring/ and /monitoring/filename.html

        String relativePath = path.substring("/monitoring".length());
        if (relativePath.startsWith("/")) {
            relativePath = relativePath.substring(1);
        }

        if (relativePath.isEmpty()) {
            listHtmlFiles(exchange);
        } else {
            serveFile(exchange, relativePath);
        }
    }

    private void listHtmlFiles(HttpExchange exchange) throws IOException {
        File folder = new File(QuicProperties.MONITORING_BASE_DIR);
        if (!folder.exists() || !folder.isDirectory()) {
            sendError(exchange, 404, "Directory not found");
            return;
        }

        File[] allFiles = folder.listFiles((_, name) -> name.toLowerCase().endsWith(".html"));

        List<String> cpuFiles = new ArrayList<>();
        List<String> memFiles = new ArrayList<>();
        List<String> nmemFiles = new ArrayList<>();

        if (allFiles != null) {
            for (File file : allFiles) {
                String name = file.getName();
                if (name.startsWith("cpu")) {
                    cpuFiles.add(name);
                } else if (name.startsWith("mem")) {
                    memFiles.add(name);
                } else if (name.startsWith("nmem")) {
                    nmemFiles.add(name);
                }
            }
        }

        Collections.sort(cpuFiles);
        Collections.sort(memFiles);
        Collections.sort(nmemFiles);

        StringBuilder response = new StringBuilder();
        response.append("<html><head><style>")
                .append(".column { float: left; width: 33.33%; }")
                .append(".row:after { content: \"\"; display: table; clear: both; }")
                .append("</style></head><body>")
                .append("<h1>jQuic live performance monitoring</h1>")
                .append("<div class=\"row\">")
                .append("<div class=\"column\"><ul>");
        
        for (String name : cpuFiles) {
            response.append("<li><a href=\"/monitoring/").append(name).append("\">").append(name).append("</a></li>");
        }
        response.append("</ul></div>")
                .append("<div class=\"column\"><ul>");

        for (String name : memFiles) {
            response.append("<li><a href=\"/monitoring/").append(name).append("\">").append(name).append("</a></li>");
        }
        response.append("</ul></div>")
                .append("<div class=\"column\"><ul>");

        for (String name : nmemFiles) {
            response.append("<li><a href=\"/monitoring/").append(name).append("\">").append(name).append("</a></li>");
        }
        response.append("</ul></div>")
                .append("</div></body></html>");

        byte[] bytes = response.toString().getBytes();
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void serveFile(HttpExchange exchange, String fileName) throws IOException {
        if (!fileName.toLowerCase().endsWith(".html")) {
            sendError(exchange, 403, "Only .html files are allowed");
            return;
        }

        // Security check for path traversal
        Path filePath = Paths.get(QuicProperties.MONITORING_BASE_DIR).resolve(fileName).normalize();
        if (!filePath.startsWith(Paths.get(QuicProperties.MONITORING_BASE_DIR))) {
            sendError(exchange, 403, "Forbidden");
            return;
        }

        File file = filePath.toFile();
        if (!file.exists() || !file.isFile()) {
            sendError(exchange, 404, "File not found");
            return;
        }

        byte[] bytes = Files.readAllBytes(filePath);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendError(HttpExchange exchange, int code, String message) throws IOException {
        byte[] bytes = message.getBytes();
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
