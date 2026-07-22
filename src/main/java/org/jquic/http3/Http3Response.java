package org.jquic.http3;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Represents an HTTP/3 response.
 */
public class Http3Response {
    private final int statusCode;
    private final String contentType;
    private final byte[] body;
    private final List<Map.Entry<String, String>> headers;

    private Http3Response(int statusCode, String contentType, byte[] body, List<Map.Entry<String, String>> headers) {
        this.statusCode = statusCode;
        this.contentType = contentType;
        this.body = body;
        this.headers = headers;
    }

    /**
     * Creates a successful response with text content.
     * 
     * @param body The response body
     * @return HTTP/3 response with status 200
     */
    public static Http3Response ok(String body, List<Map.Entry<String, String>> headers) {
        return new Http3Response(200, "text/plain; charset=utf-8", 
                                body.getBytes(StandardCharsets.UTF_8), headers);
    }

    /**
     * Creates a successful response with JSON content.
     * 
     * @param json The JSON response body
     * @return HTTP/3 response with status 200
     */
    public static Http3Response json(String json) {
        return new Http3Response(200, "application/json; charset=utf-8", 
                                json.getBytes(StandardCharsets.UTF_8), List.of());
    }

    public static Http3Response json(String json, List<Map.Entry<String, String>> headers) {
        return new Http3Response(200, "application/json; charset=utf-8",
                json.getBytes(StandardCharsets.UTF_8), headers);
    }

    /**
     * Creates a custom response.
     * 
     * @param statusCode HTTP status code
     * @param contentType Content type
     * @param body Response body
     * @return HTTP/3 response
     */
    public static Http3Response of(int statusCode, String contentType, byte[] body) {
        return new Http3Response(statusCode, contentType, body, List.of());
    }

    /**
     * Creates a 404 Not Found response.
     */
    public static Http3Response notFound() {
        return new Http3Response(404, "text/plain; charset=utf-8", 
                                "Not Found".getBytes(StandardCharsets.UTF_8), List.of());
    }

    /**
     * Creates a 500 Internal Server Error response.
     */
    public static Http3Response internalError(String message) {
        return new Http3Response(500, "text/plain; charset=utf-8", 
                                message.getBytes(StandardCharsets.UTF_8), List.of());
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getContentType() {
        return contentType;
    }

    public byte[] getBody() {
        return body;
    }

    public List<Map.Entry<String, String>> getHeaders() {
        return headers;
    }
}
