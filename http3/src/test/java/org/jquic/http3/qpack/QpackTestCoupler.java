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

import org.jspecify.annotations.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Helper class to couple QpackEncoder and QpackDecoder in tests.
 * It pipes data written to one's output stream to the other's onXxxData method.
 */
public class QpackTestCoupler {
    private final PipedOutputStream encoderToDecoder = new PipedOutputStream();
    private final PipedOutputStream decoderToEncoder = new PipedOutputStream();

    public DataOutputStream getEncoderStream() {
        return new DataOutputStream(encoderToDecoder);
    }

    public DataOutputStream getDecoderStream() {
        return new DataOutputStream(decoderToEncoder);
    }

    public void bind(Encoder encoder, Decoder decoder) {
        encoderToDecoder.setConsumer(decoder::onEncoderData);
        decoderToEncoder.setConsumer(encoder::onDecoderData);
    }

    public List<byte[]> getCapturedEncoderData() {
        return encoderToDecoder.getCaptured();
    }

    public List<byte[]> getCapturedDecoderData() {
        return decoderToEncoder.getCaptured();
    }

    public void clearCapturedData() {
        encoderToDecoder.clear();
        decoderToEncoder.clear();
    }

    private static class PipedOutputStream extends OutputStream {
        private Consumer<ByteBuffer> consumer;
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private final List<byte[]> captured = new ArrayList<>();

        public void setConsumer(Consumer<ByteBuffer> consumer) {
            this.consumer = consumer;
        }

        @Override
        public synchronized void write(int b) {
            buffer.write(b);
        }

        @Override
        public synchronized void write(byte @NonNull [] b, int off, int len) {
            buffer.write(b, off, len);
        }

        private void autoFlush() {
            if (buffer.size() > 0) {
                byte[] data = buffer.toByteArray();
                captured.add(data);
                buffer.reset();
                if (consumer != null) {
                    consumer.accept(ByteBuffer.wrap(data));
                }
            }
        }

        @Override
        public synchronized void flush() {
            autoFlush();
        }

        public synchronized List<byte[]> getCaptured() {
            return new ArrayList<>(captured);
        }

        public synchronized void clear() {
            captured.clear();
        }
    }
}
