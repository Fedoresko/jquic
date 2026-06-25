package org.fmalyshev.http3;

/**
 * Handler interface for HTTP/3 requests.
 * Implement this interface to define custom request handling logic.
 */
@FunctionalInterface
public interface Http3RequestHandler {
    /**
     * Handles an HTTP/3 request and returns a response.
     * 
     * @param request The HTTP/3 request
     * @return The HTTP/3 response
     */
    Http3Response handleRequest(Http3Request request);
}
