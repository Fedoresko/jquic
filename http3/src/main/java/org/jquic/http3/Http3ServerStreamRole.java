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
 * Represents the role of a server-initiated HTTP/3 stream as defined in RFC 9114 §6.
 */
public enum Http3ServerStreamRole {
    /** Unidirectional control stream, stream type 0x00 (RFC 9114 §6.2.1). */
    CONTROL(0x00),
    /** Unidirectional QPACK encoder stream, stream type 0x02 (RFC 9204 §4.2). */
    QPACK_ENCODER(0x02),
    /** Unidirectional QPACK decoder stream, stream type 0x03 (RFC 9204 §4.2). */
    QPACK_DECODER(0x03),
    /** Unidirectional push stream, stream type 0x01 (RFC 9114 §6.2.2). */
    PUSH(0x01);

    private final int typeValue;

    Http3ServerStreamRole(int typeValue) {
        this.typeValue = typeValue;
    }

    public int getTypeValue() {
        return typeValue;
    }
}
