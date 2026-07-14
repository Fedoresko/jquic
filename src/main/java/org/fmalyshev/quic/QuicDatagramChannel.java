package org.fmalyshev.quic;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;

import static org.fmalyshev.quic.BpfRouting.getNativeFd;

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
        return channel.send(src, target);
    }

    public SocketAddress receive(ByteBuffer dst, int[] outMetrics) throws IOException {
        if (socket != null) {
            return socket.receive(dst, outMetrics);
        } else {
            return channel.receive(dst);
        }
    }
}
