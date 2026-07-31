/*
 * Copyright 2026 Fedor Malyshev
 *
 * Licensed under the Apache License, Version 2.0 (the "License") ;
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
package org.jquic.quic;

public enum QuicVersion {
    QUIC_VERSION_1(0x00000001),
    QUIC_VERSION_2(0x6b3343cf),

    UNKNOWN(0);

    public final int val;

    QuicVersion(int val) {
        this.val = val;
    }

    public static QuicVersion of(int anInt) {
        if (anInt == QUIC_VERSION_1.val) {
            return QUIC_VERSION_1;
        } else if (anInt == QUIC_VERSION_2.val) {
            return QUIC_VERSION_2;
        } else {
            return UNKNOWN;
        }
    }
}
