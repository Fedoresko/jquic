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

public interface Encoder extends Closeable {
    // Create a new encoder initialized by encoder Stream
    static Encoder create(DataOutputStream encoderOutputStream, long maxCapacity, int indexingThreshold) {
        return new QpackEncoder(encoderOutputStream, maxCapacity, indexingThreshold);
    }

    /**
     * Encode headers
     * @param streamId the ID of the stream
     * @param headers list of headers to encode
     * @return byte buffer with raw data
     */
    ByteBuffer encodeHeaders(long streamId, List<Header> headers) throws IOException;

    /**
     *  Receive decoder instruction from peer.
     */
    void onDecoderInstruction(QpackInstruction.DecoderInstruction instruction);

    void setDynamicTableCapacity(long peerQpackMaxTableCapacity);

    /**
     * Set the maximum number of blocked streams the peer can handle.
     * @param maxBlockedStreams the maximum number of blocked streams
     */
    void setMaxBlockedStreams(long maxBlockedStreams);
}
