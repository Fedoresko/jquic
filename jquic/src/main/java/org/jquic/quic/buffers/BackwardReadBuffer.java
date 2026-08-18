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
package org.jquic.quic.buffers;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface BackwardReadBuffer {
    /**
     * Get unwrapped (original) data only starting from the provided position until the current position.
     *
     * @param position - position to get data from
     * @return - sequence of buffers containing data (if data split to different chunks there would be two and more of them).
     * @throws IllegalStateException if in history mode.
     */
    Iterable<ByteBuffer> readyContentFrom(int position);

    /**
     * Returns position for goBacks, readyContentFrom, and other...
     *
     * @return - current logical offset (number of bytes written).
     */
    int getPos();


    /**
     * Go to some previously written position to fill-in placeholder.
     * Writes performed by @{writer} would amend previously written data inplace (filling placeholders).
     *
     * @param position - position in underlying buffer.
     * @param writer   - writer to put some amendments in place
     */
    void amendAtPos(int position, ChunkedOutputStreamWithAmendments.Writer writer) throws IOException;
}
