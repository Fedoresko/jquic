/**
 * Basic HTTP/3 server implementation using QUIC protocol.
 * 
 * <p>Example usage:</p>
 * <pre>{@code
 * Http3Server server = new Http3Server(request -> {
 *     if (request.getPath().equals("/hello")) {
 *         return Http3Response.ok("Hello, HTTP/3!");
 *     }
 *     return Http3Response.notFound();
 * });
 * 
 * server.start();
 * }</pre>
 */
package org.fmalyshev.http3;
