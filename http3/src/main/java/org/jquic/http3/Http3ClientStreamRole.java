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

import org.jspecify.annotations.NonNull;

/**
 * Represents the role of a client-initiated HTTP/3 stream as defined in RFC 9114 §6.
 */
public enum Http3ClientStreamRole {
    /** Bidirectional client-initiated request stream (RFC 9114 §6.1). */
    REQUEST,
    /** Unidirectional control stream, stream type 0x00 (RFC 9114 §6.2.1). */
    CONTROL,
    /** Unidirectional QPACK encoder stream, stream type 0x02 (RFC 9204 §4.2). */
    QPACK_ENCODER,
    /** Unidirectional QPACK decoder stream, stream type 0x03 (RFC 9204 §4.2). */
    QPACK_DECODER,
    /** Grease stream type (RFC 9114 §6.2.3). */
    GREASE,
    /** Unrecognized or unsupported client-initiated unidirectional stream type. */
    UNKNOWN;

    /**
     * Maps a unidirectional stream type varint to a client-initiated role.
     *
     * @param typeValue the stream type varint value
     * @return the determined role.
     */
    @NonNull
    public static Http3ClientStreamRole fromStreamType(long typeValue) {
        return switch ((int) typeValue) {
            case 0x00 -> CONTROL;
            case 0x02 -> QPACK_ENCODER;
            case 0x03 -> QPACK_DECODER;
            default -> {
                if (typeValue >= 0x21 && (typeValue - 0x21) % 0x1f == 0) {
                    yield GREASE;
                }
                yield UNKNOWN;
            }
        };
    }
}
