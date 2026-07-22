package org.jquic.quic;

/**
 * QUIC transport error codes as defined in RFC 9000, Section 20.1.
 *
 * <p>These codes are carried in CONNECTION_CLOSE frames (type 0x1c) to signal
 * why a connection is being closed at the transport layer.  Error codes are
 * 62-bit unsigned integers on the wire; this enum covers every named code in
 * the specification plus the {@link #CRYPTO_ERROR} sentinel for the TLS-alert
 * range (0x0100 – 0x01ff).
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * // Look up from a wire value:
 * QuicTransportError err = QuicTransportError.fromCode(0x0a);  // PROTOCOL_VIOLATION
 *
 * // Build a CRYPTO_ERROR for TLS alert 40 (handshake_failure):
 * long wireCode = QuicTransportError.cryptoErrorCode(40);      // 0x0128
 * }</pre>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9000#section-20.1">RFC 9000 §20.1</a>
 */
public enum QuicTransportError {

    /**
     * An endpoint uses this with CONNECTION_CLOSE to signal that the connection
     * is being closed abruptly in the absence of any error.
     */
    NO_ERROR(0x00),

    /**
     * The endpoint encountered an internal error and cannot continue with the
     * connection.
     */
    INTERNAL_ERROR(0x01),

    /**
     * The server refused to accept a new connection.
     */
    CONNECTION_REFUSED(0x02),

    /**
     * An endpoint received more data than it permitted in its advertised data
     * limits; see Section 4 of RFC 9000.
     */
    FLOW_CONTROL_ERROR(0x03),

    /**
     * An endpoint received a frame for a stream identifier that exceeded its
     * advertised stream limit for the corresponding stream type.
     */
    STREAM_LIMIT_ERROR(0x04),

    /**
     * An endpoint received a frame for a stream that was not in a state that
     * permitted that frame.
     */
    STREAM_STATE_ERROR(0x05),

    /**
     * An endpoint received a STREAM frame containing data that exceeded the
     * previously established final size, or a final size was changed after it
     * had been established.
     */
    FINAL_SIZE_ERROR(0x06),

    /**
     * An endpoint received a frame that was badly formatted — for example, a
     * frame of an unknown type or one that contained an invalid value for a
     * field.
     */
    FRAME_ENCODING_ERROR(0x07),

    /**
     * An endpoint received transport parameters that were badly formatted,
     * included an invalid value, omitted a mandatory parameter, included a
     * forbidden parameter, or were otherwise in error.
     */
    TRANSPORT_PARAMETER_ERROR(0x08),

    /**
     * The number of connection IDs provided by the peer exceeds the advertised
     * active_connection_id_limit.
     */
    CONNECTION_ID_LIMIT_ERROR(0x09),

    /**
     * An endpoint detected an error with protocol compliance that was not
     * covered by more specific error codes.
     */
    PROTOCOL_VIOLATION(0x0a),

    /**
     * A server received a client Initial that contained an invalid Token field.
     */
    INVALID_TOKEN(0x0b),

    /**
     * The application or application protocol caused the connection to be
     * closed.
     */
    APPLICATION_ERROR(0x0c),

    /**
     * An endpoint's CRYPTO data buffer became full and the peer is still
     * sending CRYPTO frames.
     */
    CRYPTO_BUFFER_EXCEEDED(0x0d),

    /**
     * An endpoint detected errors in performing key updates; see Section 6 of
     * RFC 9001.
     */
    KEY_UPDATE_ERROR(0x0e),

    /**
     * An endpoint has reached the confidentiality or integrity limit for the
     * AEAD algorithm used by the given connection.
     */
    AEAD_LIMIT_REACHED(0x0f),

    /**
     * A path validation failed; see Section 8.2 of RFC 9000.
     */
    NO_VIABLE_PATH(0x10),

    /**
     * Sentinel for the CRYPTO_ERROR range (0x0100 – 0x01ff).
     *
     * <p>The low 8 bits of the wire value encode the TLS alert code that
     * caused the closure.  Use {@link #cryptoErrorCode(int)} to construct the
     * correct wire value, and {@link #isCryptoError(long)} to detect it during
     * parsing.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9000#section-20.1">RFC 9000 §20.1</a>
     */
    CRYPTO_ERROR(0x0100),

    TLS_ERROR_UNEXPECTED_MESSAGE(0x0100 + 10),
    TLS_ERROR_BAD_RECORD_MAC(0x0100 + 20),
    TLS_ERROR_RECORD_OVERFLOW(0x0100 + 22),
    TLS_ERROR_HANDSHAKE_FAILURE(0x0100 + 40),
    TLS_ERROR_BAD_CERTIFICATE(0x0100 + 42),
    TLS_ERROR_UNSUPPORTED_CERTIFICATE(0x0100 + 43),
    TLS_ERROR_CERTIFICATE_REVOKED(0x0100 + 44),
    TLS_ERROR_CERTIFICATE_EXPIRED(0x0100 + 45),
    TLS_ERROR_CERTIFICATE_UNKNOWN(0x0100 + 46),
    TLS_ERROR_ILLEGAL_PARAMETER(0x0100 + 47),
    TLS_ERROR_UNKNOWN_CA(0x0100 + 48),
    TLS_ERROR_ACCESS_DENIED(0x0100 + 49),
    TLS_ERROR_DECODE_ERROR(0x0100 + 50),
    TLS_ERROR_DECRYPT_ERROR(0x0100 + 51),
    TLS_ERROR_PROTOCOL_VERSION(0x0100 + 70),
    TLS_ERROR_INSUFFICIENT_SECURITY(0x0100 + 71),
    TLS_ERROR_INTERNAL_ERROR(0x0100 + 80),
    TLS_ERROR_INAPPROPRIATE_FALLBACK(0x0100 + 86),
    TLS_ERROR_USER_CANCELED(0x0100 + 90),
    TLS_ERROR_MISSING_EXTENSION(0x0100 + 109),
    TLS_ERROR_UNSUPPORTED_EXTENSION(0x0100 + 110),
    TLS_ERROR_UNRECOGNIZED_NAME(0x0100 + 112),
    TLS_ERROR_BAD_CERTIFICATE_STATUS_RESPONSE(0x0100 + 113),
    TLS_ERROR_UNKNOWN_PSK_IDENTITY(0x0100 + 115),
    TLS_ERROR_CERTIFICATE_REQUIRED(0x0100 + 116),
    TLS_ERROR_NO_APPLICATION_PROTOCOL(0x0100 + 120);

    // ─────────────────────────────────────────────────────────────────────────

    private final long code;

    QuicTransportError(long code) {
        this.code = code;
    }

    /**
     * Returns the wire value of this error code.
     *
     * <p>For {@link #CRYPTO_ERROR} this returns the base value {@code 0x0100};
     * use {@link #cryptoErrorCode(int)} to obtain a code that also encodes the
     * specific TLS alert.
     */
    public long code() {
        return code;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Factory / reverse-lookup helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns the enum constant whose wire value equals {@code code}, or
     * {@link #PROTOCOL_VIOLATION} as a safe fallback for unknown values.
     *
     * <p>Values in the range {@code 0x0100}–{@code 0x01ff} are mapped to
     * {@link #CRYPTO_ERROR} regardless of the specific TLS alert byte.
     *
     * @param code wire error code read from a CONNECTION_CLOSE frame
     * @return the matching {@link QuicTransportError}
     */
    public static QuicTransportError fromCode(long code) {
        if (isCryptoError(code)) {
            return CRYPTO_ERROR;
        }
        for (QuicTransportError e : values()) {
            if (e.code == code) {
                return e;
            }
        }
        // Unknown codes are treated as a protocol violation per RFC 9000 §20.1
        return PROTOCOL_VIOLATION;
    }

    /**
     * Returns {@code true} when {@code code} falls in the CRYPTO_ERROR range
     * {@code 0x0100}–{@code 0x01ff}, indicating a TLS alert was the cause.
     *
     * @param code wire error code read from a CONNECTION_CLOSE frame
     */
    public static boolean isCryptoError(long code) {
        return code >= 0x0100L && code <= 0x01ffL;
    }

    /**
     * Builds the wire error code for a TLS-alert-triggered connection close.
     *
     * <p>Per RFC 9000 §20.1: the error code is {@code 0x0100 + alertCode},
     * where {@code alertCode} is the TLS alert description value (0–255).
     *
     * @param tlsAlertCode TLS alert description value (0–255)
     * @return wire transport error code to place in a CONNECTION_CLOSE frame
     * @throws IllegalArgumentException if {@code tlsAlertCode} is not in 0–255
     */
    public static long cryptoErrorCode(int tlsAlertCode) {
        if (tlsAlertCode < 0 || tlsAlertCode > 0xff) {
            throw new IllegalArgumentException(
                "TLS alert code must be in range 0–255, got: " + tlsAlertCode);
        }
        return 0x0100L + tlsAlertCode;
    }

    /**
     * Extracts the TLS alert description byte from a CRYPTO_ERROR wire value.
     *
     * @param code wire error code that must satisfy {@link #isCryptoError(long)}
     * @return TLS alert description (0–255)
     * @throws IllegalArgumentException if {@code code} is not a CRYPTO_ERROR
     */
    public static int extractTlsAlert(long code) {
        if (!isCryptoError(code)) {
            throw new IllegalArgumentException(
                "Not a CRYPTO_ERROR wire code: 0x" + Long.toHexString(code));
        }
        return (int) (code & 0xffL);
    }

    @Override
    public String toString() {
        return name() + "(0x" + Long.toHexString(code) + ")";
    }
}
