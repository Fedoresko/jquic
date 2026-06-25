package org.fmalyshev.http3;

/**
 * Represents an HTTP/3 request.
 */
public class Http3Request {
    private final long connectionId;
    private final String method;
    private final String path;

    public String data = "";

    Http3Request(long connectionId, String method, String path) {
        this.connectionId = connectionId;
        this.method = method;
        this.path = path;
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

    @Override
    public String toString() {
        return String.format("Http3Request{connection=%d, method=%s, path=%s}", 
                           connectionId, method, path);
    }
}
