package org.jquic.hqinterop;

/**
 * Handler interface for hq-interop (HTTP/0.9) requests.
 */
@FunctionalInterface
public interface HqInteropRequestHandler {
    /**
     * Handles a GET request and returns the response data.
     *
     * @param path The request path
     * @return The response bytes
     */
    byte[] handleGet(String path);
}
