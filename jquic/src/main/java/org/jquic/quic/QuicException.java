package org.jquic.quic;

/**
 * Exception thrown when cryptographic operations fail.
 */
public class QuicException extends Exception {
    private final Short demandedGroupId;
    private final QuicTransportError error;

    public Short getDemandedGroupId() {
        return demandedGroupId;
    }

    public QuicTransportError getError() {
        return error;
    }

    public QuicException(String message, QuicTransportError error) {
        super(message);
        this.error = error;
        demandedGroupId = null;
    }

    public QuicException(String message) {
        super(message);
        demandedGroupId = null;
        this.error = null;
    }

    public QuicException(String message, short demandedGroupId) {
        super(message);
        this.demandedGroupId = demandedGroupId;
        this.error = null;
    }

    public QuicException(String message, Throwable cause) {
        super(message, cause);
        demandedGroupId = null;
        this.error = null;
    }
}
