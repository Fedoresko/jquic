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

import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.BiFunction;

public class QpackBlockingManager {
    private final long maxBlockedStreams;
    private final Map<Long, BlockedStream> blockedStreams = new LinkedHashMap<>();
    private final Map<Long, List<BlockedStream>> streamsByRequiredInsertCount = new HashMap<>();
    private Decoder.UnblockedStreamListener unblockedStreamListener;

    private final BiFunction<Long, ByteBuffer, List<Header>> decodeCallback;

    private record BlockedStream(long streamId, ByteBuffer frame, long requiredInsertCount) {}

    public QpackBlockingManager(long maxBlockedStreams, BiFunction<Long, ByteBuffer, List<Header>> decodeCallback) {
        this.maxBlockedStreams = maxBlockedStreams;
        this.decodeCallback = decodeCallback;
    }

    public void setUnblockedStreamListener(Decoder.UnblockedStreamListener listener) {
        this.unblockedStreamListener = listener;
    }

    public void blockStream(long streamId, ByteBuffer frame, long requiredInsertCount) {
        if (blockedStreams.size() >= maxBlockedStreams) {
            throw new QpackException(QpackException.QPACK_DECOMPRESSION_FAILED,
                    "Maximum number of blocked streams exceeded: " + maxBlockedStreams);
        }

        byte[] blockData = new byte[frame.remaining()];
        frame.get(blockData);

        BlockedStream blocked = new BlockedStream(streamId, ByteBuffer.wrap(blockData), requiredInsertCount);
        blockedStreams.put(streamId, blocked);
        streamsByRequiredInsertCount.computeIfAbsent(requiredInsertCount, _ -> new ArrayList<>()).add(blocked);
    }

    public void tryUnblockStreams(long currentInsertCount) {
        List<Long> RicsToUnblock = new ArrayList<>();
        for (long ric : streamsByRequiredInsertCount.keySet()) {
            if (ric <= currentInsertCount) {
                RicsToUnblock.add(ric);
            }
        }

        Collections.sort(RicsToUnblock);

        for (long ric : RicsToUnblock) {
            List<BlockedStream> blocked = streamsByRequiredInsertCount.remove(ric);
            if (blocked != null) {
                for (BlockedStream bs : blocked) {
                    blockedStreams.remove(bs.streamId());
                    try {
                        List<Header> headers = decodeCallback.apply(bs.streamId(), bs.frame());
                        if (unblockedStreamListener != null) {
                            unblockedStreamListener.onHeadersDecoded(bs.streamId(), headers);
                        }
                    } catch (Exception e) {
                        if (unblockedStreamListener != null) {
                            unblockedStreamListener.onDecodingError(bs.streamId(), e);
                        }
                    }
                }
            }
        }
    }

    public void cancelStream(long streamId) {
        BlockedStream removed = blockedStreams.remove(streamId);
        if (removed != null) {
            List<BlockedStream> list = streamsByRequiredInsertCount.get(removed.requiredInsertCount());
            if (list != null) {
                list.remove(removed);
                if (list.isEmpty()) {
                    streamsByRequiredInsertCount.remove(removed.requiredInsertCount());
                }
            }
        }
    }
}
