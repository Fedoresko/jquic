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

import java.nio.ByteBuffer;
import java.util.function.BiConsumer;

public class TranscryptHashSupport {

    private final BiConsumer<ByteBuffer, String> transcryptHashUpdater;
    private final ChunkedOutputStreamWithAmendmentsImpl stream;
    private String currentMessage;
    private int prevMessageOffset;

    public TranscryptHashSupport(ChunkedOutputStreamWithAmendmentsImpl stream, BiConsumer<ByteBuffer, String> transcryptHashUpdater) {
        this.transcryptHashUpdater = transcryptHashUpdater;
        prevMessageOffset = stream.getPos();
        this.stream = stream;
    }

    public void startHashMessage(String message) {
        updateTranscryptHash();
        currentMessage = message;
    }

    private void updateTranscryptHash() {
        if (currentMessage != null) {
            for (ByteBuffer buf : stream.readyContentFrom(prevMessageOffset)) {
                transcryptHashUpdater.accept(buf, currentMessage);
                prevMessageOffset = stream.getPos();
            }
        }
    }

    public void finish() {
        updateTranscryptHash();
    }
}


