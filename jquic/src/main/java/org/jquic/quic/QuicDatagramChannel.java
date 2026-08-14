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
package org.jquic.quic;

import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.linux.ECT;
import org.jquic.quic.linux.LinuxEcnSocket;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.jquic.quic.linux.NativeUtil.getNativeFd;

public class QuicDatagramChannel {
    private static final Logger logger = LoggerFactory.getLogger(QuicDatagramChannel.class);

    private final DatagramChannel channel;
    private final LinuxEcnSocket socket;

    public QuicDatagramChannel(DatagramChannel channel) throws IOException {
        this.channel = channel;
        channel.configureBlocking(false);
        socket = getLinuxEcnSocket(channel);
    }

    private static @Nullable LinuxEcnSocket getLinuxEcnSocket(DatagramChannel channel) {
        try {
            return new LinuxEcnSocket(getNativeFd(channel));
        } catch (Exception e) {
            logger.warn("Failed to open Linux EcnSocket. ECN is not supported.");
            return null;
        }
    }

    public int send(ByteBuffer src, SocketAddress target, ECT ectMarking)
            throws IOException {
        if (socket != null) {
            InetSocketAddress socketAddress = (InetSocketAddress)target;
            return (int) socket.send(src, buildSockAddr(socketAddress.getAddress().getAddress(), socketAddress.getPort()), ectMarking);
        } else {
            return channel.send(src, target);
        }
    }

    public int sendBatch(Collection<SelectorThread.PacketToSend> data) throws IOException {
        if (socket != null) {
            return socket.sendBatch(data);
        } else {
            for (SelectorThread.PacketToSend entry : data) {
                channel.send(entry.poolBuffer().buf(), entry.socketAddress());
            }
            return data.size();
        }
    }

    public SocketAddress receive(ByteBuffer dst, int[] outMetrics) throws IOException {
        if (socket != null) {
            return socket.receive(dst, outMetrics);
        } else {
            return channel.receive(dst);
        }
    }

    public List<ReceivedPacket> receiveBatch(PoolBuffer[] buffers) throws IOException {
        int maxCount = buffers.length;
        if (socket != null) {
            return socket.receiveBatch(buffers);
        } else {
            List<ReceivedPacket> results = new ArrayList<>();
            for (PoolBuffer buffer : buffers) {
                ByteBuffer buf = buffer.buf();
                buf.clear();
                int startPos = buf.position();
                SocketAddress sender = channel.receive(buf);
                if (sender == null) {
                    break;
                }
                buf.limit(buf.position());
                buf.position(startPos);
                results.add(new ReceivedPacket(buffer, sender, 0));
            }
            return results;
        }
    }

    public List<ReceivedPacket> receiveBatchBlocking(PoolBuffer[] buffers) throws IOException {
        if (socket != null) {
            return socket.receiveBatchBlocking(buffers);
        } else {
            List<ReceivedPacket> results = new ArrayList<>();
            for (int i = 0; i < buffers.length; i++) {
                ByteBuffer buf = buffers[i].buf();
                buf.clear();
                int startPos = buf.position();
                SocketAddress sender;
                if (i == 0) {
                    sender = receiveBlocking(buf, null);
                } else {
                    sender = channel.receive(buf);
                }

                if (sender == null) {
                    break;
                }
                buf.limit(buf.position());
                buf.position(startPos);
                results.add(new ReceivedPacket(buffers[i], sender, 0));
            }
            return results;
        }
    }

    public SocketAddress receiveBlocking(ByteBuffer dst, int[] outMetrics) throws IOException {
        if (socket != null) {
            return socket.receiveBlocking(dst, outMetrics);
        } else {
            try (Selector idleSelector = Selector.open()) {
                channel.register(idleSelector, SelectionKey.OP_READ);
                idleSelector.select(10);
                return channel.receive(dst);
            }
        }
    }

    public record ReceivedPacket(PoolBuffer data, SocketAddress sender, int ecnFlags) {
    }

    public static int[] buildSockAddr(byte[] ip, int port) {
        // 1. sin_family (2 bytes) + sin_port (2 bytes, big-endian)
        short sin_family = 2; // AF_INET
        short sin_port = Short.reverseBytes((short) port);
        int word0 = ((sin_port & 0xFFFF) << 16) | (sin_family & 0xFFFF);

        // 2. sin_addr (4 bytes, big-endian IP)
        int word1 = ((ip[3] & 0xFF) << 24) | ((ip[2] & 0xFF) << 16) | ((ip[1] & 0xFF) << 8) | (ip[0] & 0xFF);

        // 3. sin_zero padding (8 bytes of zeros = 2 int words)
        int word2 = 0;
        int word3 = 0;

        return new int[]{ word0, word1, word2, word3 };
    }
}

