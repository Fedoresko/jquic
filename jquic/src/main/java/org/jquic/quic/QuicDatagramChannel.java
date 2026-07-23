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

    public int send(ByteBuffer src, SocketAddress target)
            throws IOException {
        if (socket != null) {
            InetSocketAddress socketAddress = (InetSocketAddress)target;
            return (int) socket.send(src, buildSockAddr(socketAddress.getHostName(), socketAddress.getPort()));
        } else {
            return channel.send(src, target);
        }
    }

    public static int[] buildSockAddr(String ip, int port) {
        String[] parts = ip.split("\\.");

        // 1. sin_family (2 bytes) + sin_port (2 bytes, big-endian)
        short sin_family = 2; // AF_INET
        short sin_port = Short.reverseBytes((short) port);
        int word0 = ((sin_port & 0xFFFF) << 16) | (sin_family & 0xFFFF);

        // 2. sin_addr (4 bytes, big-endian IP)
        byte b0 = (byte) Integer.parseInt(parts[0]);
        byte b1 = (byte) Integer.parseInt(parts[1]);
        byte b2 = (byte) Integer.parseInt(parts[2]);
        byte b3 = (byte) Integer.parseInt(parts[3]);
        int word1 = ((b3 & 0xFF) << 24) | ((b2 & 0xFF) << 16) | ((b1 & 0xFF) << 8) | (b0 & 0xFF);

        // 3. sin_zero padding (8 bytes of zeros = 2 int words)
        int word2 = 0;
        int word3 = 0;

        return new int[]{ word0, word1, word2, word3 };
    }

    public SocketAddress receive(ByteBuffer dst, int[] outMetrics) throws IOException {
        if (socket != null) {
            return socket.receive(dst, outMetrics);
        } else {
            return channel.receive(dst);
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
}

