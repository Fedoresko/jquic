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
            return (int) socket.send(src, (InetSocketAddress)target, ectMarking);
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

    public ReceivedPacket receive(PoolBuffer dst) throws IOException {
        if (socket != null) {
            return socket.receive(dst);
        } else {
            SocketAddress sender = channel.receive(dst.buf().rewind());
            if (sender == null) return null;
            dst.buf().flip();
            return new ReceivedPacket(dst, sender, 0);
        }
    }

    public List<ReceivedPacket> receiveBatch(PoolBuffer[] buffers) throws IOException {
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
                if (i == 0) {
                    results.add( receiveBlocking(buffers[i]) );
                } else {
                    results.add( receive(buffers[i]) );
                }
            }
            return results;
        }
    }

    public ReceivedPacket receiveBlocking(PoolBuffer dst) throws IOException {
        if (socket != null) {
            return socket.receiveBlocking(dst);
        } else {
            try (Selector idleSelector = Selector.open()) {
                channel.register(idleSelector, SelectionKey.OP_READ);
                idleSelector.select(10);
                SocketAddress sender = channel.receive(dst.buf().rewind());
                dst.buf().flip();
                return new  ReceivedPacket(dst, sender, 0);
            }
        }
    }

    public record ReceivedPacket(PoolBuffer data, SocketAddress sender, int ecnFlags) {
    }
}

