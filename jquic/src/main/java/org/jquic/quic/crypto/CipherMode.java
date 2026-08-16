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
package org.jquic.quic.crypto;

/**
 * TLS_AES_128_GCM_SHA256 cipher suite identifier (RFC 8446 Appendix B.4).
 */
public enum CipherMode {
    TLS_AES_128_GCM_SHA256_ID(0x1301, 16),
    TLS_AES_256_GCM_SHA384_ID(0x1302, 32),
    TLS_CHACHA20_POLY1305_SHA256(0x1303, 32),
    UNKNOWN(0, 0);

    CipherMode(int val, int keyLen) {
        this.val = val;
        this.keyLen = keyLen;
    }

    public static CipherMode fromInt(int val) {
        for (CipherMode mode : values()) {
            if (mode.val == val) {
                return mode;
            }
        }
        return UNKNOWN;
    }

    public final int val;
    public final int keyLen;
}
