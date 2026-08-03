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

import java.io.Closeable;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

public interface Decoder extends Closeable{

    // Create a new decoder initialized by decoder Stream
    static Decoder create(DataOutputStream decoderOutputStream, long maxTableCapacity) {
        return new QpackDecoder(decoderOutputStream, maxTableCapacity);
    }

    /**
     * Decode headers
     * @param streamId the ID of the stream
     * @param frame byte buffer with raw data
     * @return list of decoded headers
     * @throws QpackRequiredInsertCountException if the stream is blocked
     * @throws IOException on decoding error
     */
    List<Header> decodeHeaders(long streamId, ByteBuffer frame) throws IOException;

    /**
     * Listener for blocked streams that become unblocked.
     */
    interface UnblockedStreamListener {
        void onHeadersDecoded(long streamId, List<Header> headers);
        void onDecodingError(long streamId, Exception e);
    }

    /**
     * Set a listener to be triggered when dynamic table's insertCount is updated.
     * @param listener consumer of the new insertCount
     */
    void setUnblockedStreamListener(java.util.function.Consumer<Long> listener);

    /**
     *  Receive encoder instruction from peer.
     */
    void onEncoderInstruction(QpackInstruction.EncoderInstruction instruction);

    /**
     * Cancel a stream.
     * @param streamId the ID of the stream to cancel
     */
    void cancelStream(long streamId);
}