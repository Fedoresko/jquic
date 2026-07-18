package org.fmalyshev.http3;

/**
 * Represents the role of an HTTP/3 stream as defined in RFC 9114 §6.
 *
 * <p>Bidirectional streams are always {@link #REQUEST} streams.
 * Unidirectional streams declare their role via a stream-type varint
 * written at the very lower of the stream:
 * <ul>
 *   <li>{@code 0x00} — {@link #CONTROL}</li>
 *   <li>{@code 0x02} — {@link #QPACK_ENCODER}</li>
 *   <li>{@code 0x03} — {@link #QPACK_DECODER}</li>
 * </ul>
 * Any other type value maps to {@link #UNKNOWN}.
 */
enum Http3StreamRole {
    /** Bidirectional client-initiated request stream (RFC 9114 §4). */
    REQUEST,
    /** Unidirectional control stream, stream type 0x00 (RFC 9114 §6.2.1). */
    CONTROL,
    /** Unidirectional QPACK encoder stream, stream type 0x02 (RFC 9204 §4.2). */
    QPACK_ENCODER,
    /** Unidirectional QPACK decoder stream, stream type 0x03 (RFC 9204 §4.2). */
    QPACK_DECODER,
    /** Unidirectional push stream, stream type 0x01 (RFC 9114 §6.2.2). */
    PUSH,
    /** Role not yet determined — waiting for the stream-type varint on a unidirectional stream. */
    UNKNOWN
}
