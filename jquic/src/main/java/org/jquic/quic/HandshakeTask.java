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

import java.net.SocketAddress;

/**
 * Encapsulates a handshake task to be processed by any available SelectorThread.
 * The CID is pre-allocated by the AcceptorThread.
 */
public class HandshakeTask {
    final PoolBuffer packet;
    final SocketAddress sender;
    final long allocatedCid;
    final QuicPacketHeader.PacketSummary packetSummary;

    HandshakeTask(PoolBuffer packet, SocketAddress sender, long allocatedCid, QuicPacketHeader.PacketSummary packetSummary) {
        this.packet = packet;
        this.sender = sender;
        this.allocatedCid = allocatedCid;
        this.packetSummary = packetSummary;
    }
}

