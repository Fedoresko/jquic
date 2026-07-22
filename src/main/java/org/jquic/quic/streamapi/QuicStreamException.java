package org.jquic.quic.streamapi;

public class QuicStreamException extends Exception {
    public QuicStreamException(String message, Exception e) {
        super(message, e);
    }
    public QuicStreamException(String message) {
        super(message);
    }
}
