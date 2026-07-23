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

/**
 * Represents an HTTP/3 request.
 */
public class Http3Request {
    private final long connectionId;
    private final String method;
    private final String path;
    private final Long contentLength;

    public String data = "";

    Http3Request(long connectionId, String method, String path, Long contentLength) {
        this.connectionId = connectionId;
        this.method = method;
        this.path = path;
        this.contentLength = contentLength;
    }

    /**
     * Gets the QUIC connection ID.
     */
    public long getConnectionId() {
        return connectionId;
    }

    /**
     * Gets the HTTP method (GET, POST, etc.).
     */
    public String getMethod() {
        return method;
    }

    /**
     * Gets the request path.
     */
    public String getPath() {
        return path;
    }

    public Long getContentLength() {
        return contentLength;
    }

    public void appendBody(String body) {
        data += body;
    }

    @Override
    public String toString() {
        return String.format("Http3Request{connection=%d, method=%s, path=%s}", 
                           connectionId, method, path);
    }
}

