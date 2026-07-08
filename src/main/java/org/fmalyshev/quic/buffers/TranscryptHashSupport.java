package org.fmalyshev.quic.buffers;

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

