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
package org.jquic.quic.paths;

import org.jquic.quic.packets.WindowedStatCounter;
import org.jquic.quic.streamapi.CongestionControl;

import java.net.InetSocketAddress;

public class ConnectionPath {
    public final InetSocketAddress address;
    public long lastActive;
    public long probeSentAt;
    public long receivedBytes;
    public long sentBytes;
    public long createdAt;
    public long bytesLastBlocked;
    public long bytesAcked;
    public long nextSendSchedNs;
    public byte[] challenge;
    public PathState state;
    public DatagramToSend nextDatagram;
    public CongestionControl congestionControl;
    public WindowedStatCounter windowedStatCounter;

    public ConnectionPath(InetSocketAddress address, long now, int timeWindowMs) {
        this.address = address;
        this.state = PathState.NEW;
        this.lastActive = now;
        this.createdAt = lastActive;
        this.windowedStatCounter = new WindowedStatCounter(timeWindowMs);
    }
}
