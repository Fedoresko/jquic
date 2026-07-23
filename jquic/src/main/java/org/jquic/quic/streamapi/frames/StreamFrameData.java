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
package org.jquic.quic.streamapi.frames;

import org.jquic.quic.buffers.PoolBuffer;

public class StreamFrameData implements ProtocolFrame {
    public final long streamId;
    public final long offset;
    public final PoolBuffer data;
    public final boolean fin;

    public StreamFrameData(long streamId, long offset, PoolBuffer data, boolean fin) {
        this.streamId = streamId;
        this.offset = offset;
        this.data = data;
        this.fin = fin;
    }

    @Override
    public int size() {
        return 20 + data.buf().remaining();
    }
}

