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
 * Represents the role of an HTTP/3 stream as defined in RFC 9114 В§6.
 *
 * <p>Bidirectional streams are always {@link #REQUEST} streams.
 * Unidirectional streams declare their role via a stream-type varint
 * written at the very lower of the stream:
 * <ul>
 *   <li>{@code 0x00} вЂ” {@link #CONTROL}</li>
 *   <li>{@code 0x02} вЂ” {@link #QPACK_ENCODER}</li>
 *   <li>{@code 0x03} вЂ” {@link #QPACK_DECODER}</li>
 * </ul>
 * Any other type value maps to {@link #UNKNOWN}.
 */
enum Http3StreamRole {
    /** Bidirectional client-initiated request stream (RFC 9114 В§4). */
    REQUEST,
    /** Unidirectional control stream, stream type 0x00 (RFC 9114 В§6.2.1). */
    CONTROL,
    /** Unidirectional QPACK encoder stream, stream type 0x02 (RFC 9204 В§4.2). */
    QPACK_ENCODER,
    /** Unidirectional QPACK decoder stream, stream type 0x03 (RFC 9204 В§4.2). */
    QPACK_DECODER,
    /** Unidirectional push stream, stream type 0x01 (RFC 9114 В§6.2.2). */
    PUSH,
    /** Role not yet determined вЂ” waiting for the stream-type varint on a unidirectional stream. */
    UNKNOWN
}

