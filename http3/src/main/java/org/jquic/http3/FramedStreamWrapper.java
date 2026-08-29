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

import org.jquic.quic.QuicVarint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Deque;

public class FramedStreamWrapper implements StreamWrapper {
    private final Http3StreamContext context;
    private final Deque<Http3StreamContext.ParsedFrame> frames = new ArrayDeque<>();
    private ByteArrayOutputStream currentFrame = new ByteArrayOutputStream(2048);
    private Long curType = null;
    private Long curLen = null;
    private int framesReturned = 0;
    private int startFramePos = 0;

    public FramedStreamWrapper(Http3StreamContext context) {
        this.context = context;
    }

    private void processMoreData() throws IOException {
        int byteread;
        while ((byteread = context.read()) != -1) {
            currentFrame.write(byteread);
        }

        ByteBuffer wrap = ByteBuffer.wrap(currentFrame.toByteArray()).position(startFramePos).limit(currentFrame.size());

        if (curType == null || curLen == null) {
            try {
                if (wrap.hasRemaining()) curType = QuicVarint.read(wrap);
                if (wrap.hasRemaining()) curLen = QuicVarint.read(wrap);
            } catch (BufferOverflowException | BufferUnderflowException e) {
                curType = null;
                curLen = null;
            }
        }

        if (curType == null || curLen == null) {
            wrap.position(startFramePos);
        }

        if (curType != null && curLen != null && wrap.remaining() >= curLen) {
            byte[] data = new byte[curLen.intValue()];
            wrap.get(data);
            frames.push(new Http3StreamContext.ParsedFrame(curType, data));
            startFramePos = wrap.position();
            curLen = null;
            curType = null;
        }

        if (currentFrame.size() != wrap.remaining()) {
            currentFrame = new ByteArrayOutputStream(2048);
            while (wrap.hasRemaining()) {
                currentFrame.write(wrap.get());
            }
            startFramePos = 0;
        }
    }

    public int framesReturned() {
        return framesReturned;
    }

    public Http3StreamContext.ParsedFrame getNextFrame() throws IOException {
        processMoreData();
        Http3StreamContext.ParsedFrame res = frames.poll();
        if (res != null) framesReturned++;
        return res;
    }
}
