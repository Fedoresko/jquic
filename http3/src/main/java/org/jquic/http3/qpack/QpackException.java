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
package org.jquic.http3.qpack;

public class QpackException extends RuntimeException {
    private final int errorCode;
    public QpackException(int errorCode, String message) {
        this.errorCode = errorCode;
        super(message);
    }
    public int getErrorCode() {
        return errorCode;
    }

    public static final int QPACK_DECOMPRESSION_FAILED = 0x0200; //	The decoder failed to interpret an encoded field section and is not able to continue decoding that field section
    public static final int QPACK_ENCODER_STREAM_ERROR = 0x0201; //	The decoder failed to interpret an encoder instruction received on the encoder stream
    public static final int QPACK_DECODER_STREAM_ERROR = 0x0202; // The encoder failed to interpret a decoder instruction received on the decoder stream.

    @Override
    public String toString() {
        return "QpackException{errorCode=" + String.format("0x%04X", errorCode) + ", message=" + getMessage() + "}";
    }
}
