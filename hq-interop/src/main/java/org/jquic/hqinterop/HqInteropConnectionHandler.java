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
package org.jquic.hqinterop;
 
import org.jquic.quic.streamapi.QuicApplicationProtocolConnectionHandler;
import org.jquic.quic.streamapi.QuicConnectionControl;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
 
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
 
public class HqInteropConnectionHandler implements QuicApplicationProtocolConnectionHandler {
    private static final Logger logger = LoggerFactory.getLogger(HqInteropConnectionHandler.class);

    private final HqInteropRequestHandler requestHandler;
    private final Map<Long, ByteArrayOutputStream> requestBuffers = new ConcurrentHashMap<>();
    private final Map<Long, DataOutputStream> outputStreams = new ConcurrentHashMap<>();
 
    public HqInteropConnectionHandler(HqInteropRequestHandler requestHandler) {
        this.requestHandler = requestHandler;
    }
 
    @Override
    public void onNewServerStreamAllocated(long streamId, @NonNull DataOutputStream outputStream, QuicConnectionControl.StreamType streamType) {
        logger.debug("New server stream allocated: {} ({})", streamId, streamType);
    }
 
    @Override
    public void onNewClientStreamAllocated(long streamId, @NonNull QuicConnectionControl control, @Nullable DataOutputStream outputStream, QuicConnectionControl.StreamType streamType) {
        logger.debug("New client stream allocated: {} ({})", streamId, streamType);
        if (streamType == QuicConnectionControl.StreamType.Bidirectional) {
            requestBuffers.put(streamId, new ByteArrayOutputStream());
            if (outputStream != null) {
                outputStreams.put(streamId, outputStream);
            }
        }
    }
 
    @Override
    public void onStreamDataReceived(long streamId, @NonNull QuicConnectionControl control, byte[] data, boolean isLastData, @Nullable Long errorCode) {
        ByteArrayOutputStream buffer = requestBuffers.get(streamId);
        if (buffer != null) {
            try {
                buffer.write(data);
                if (isLastData) {
                    processRequest(streamId, buffer.toByteArray());
                    requestBuffers.remove(streamId);
                }
            } catch (IOException e) {
                logger.error("Error writing to stream buffer", e);
            }
        }
    }
 
    private void processRequest(long streamId, byte[] requestData) {
        String request = new String(requestData, StandardCharsets.UTF_8).trim();
        logger.info("Received hq-interop request on stream {}: '{}'", streamId, request);
 
        if (request.startsWith("GET ")) {
            String path = request.substring(4).trim();
            handleGet(streamId, path);
        } else {
            logger.warn("Invalid hq-interop request on stream {}: {}", streamId, request);
            closeStreamSilently(streamId);
        }
    }
 
    private void handleGet(long streamId, String path) {
        DataOutputStream outputStream = outputStreams.remove(streamId);
        if (outputStream == null) {
            logger.warn("No output stream for bidirectional stream {}", streamId);
            return;
        }

        Thread.startVirtualThread(() -> {
            try {
                byte[] responseBytes = requestHandler.handleGet(path);
                outputStream.write(responseBytes);
                // In HTTP/0.9 over QUIC, the server MUST send FIN after the response.
                // In this API, closing the DataOutputStream might send FIN.
                outputStream.close();
                logger.debug("Sent response and closed stream {}", streamId);
            } catch (IOException e) {
                logger.error("Error sending hq-interop response on stream {}", streamId, e);
            }
        });
    }
 
    private void closeStreamSilently(long streamId) {
        DataOutputStream os = outputStreams.remove(streamId);
        if (os != null) {
            try {
                os.close();
            } catch (IOException ignored) {}
        }
    }
 
    @Override
    public void onDatagramReceived(byte[] data, @NonNull QuicConnectionControl control) {
    }
 
    @Override
    public void setOutgoingDatagramStream(@NonNull DataOutputStream outputStream) {
    }
 
    @Override
    public void onConnectionClose() {
        requestBuffers.clear();
    }
}
