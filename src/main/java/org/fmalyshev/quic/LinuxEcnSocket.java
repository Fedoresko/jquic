package org.fmalyshev.quic;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;

public class LinuxEcnSocket {
    private static boolean isJniLibraryLoaded = false;

    static {
        try {
            System.loadLibrary("quic_ecn");
            isJniLibraryLoaded = true;
        } catch (Throwable t) {
            isJniLibraryLoaded = false;
        }
    }

    private final int fd;

    public LinuxEcnSocket(int fd) throws Exception {
        if (!isJniLibraryLoaded) {
            throw new Exception("LinuxEcnSocket is not loaded");
        }
        this.fd = fd;
    }

    /**
     * Natively reads a UDP packet from the given file descriptor.
     *
     * @param fd         The raw native Linux socket file descriptor
     * @param dst        The destination ByteBuffer (Supports both Direct and Heap buffers)
     * @param outMetrics An array of size 1 where the native layer writes the extracted ECN bits
     * @return The SocketAddress of the remote sender, or null if no packet was available (EAGAIN)
     * @throws IOException If a native socket error occurs
     */
    private static native SocketAddress nativeReceive(int fd, ByteBuffer dst, int position, int limit, int[] outMetrics) throws IOException;

    public SocketAddress receive(ByteBuffer dst, int[] outMetrics) throws IOException {
        if (dst.isReadOnly()) {
            throw new IllegalArgumentException("Read-only buffer");
        }
        if (outMetrics == null || outMetrics.length < 1) {
            throw new IllegalArgumentException("outMetrics array must be at least size 1");
        }

        int position = dst.position();
        int limit = dst.limit();
        int remaining = limit - position;

        if (remaining <= 0) {
            return null;
        }

        // Execute native receive
        SocketAddress sender = nativeReceive(fd, dst, position, limit, outMetrics);

        if (sender != null) {
            int packed = outMetrics[0];

            // Extract the length from the upper 26 bits
            int bytesRead = packed >>> 6;
            dst.position(position + bytesRead);

            // Leave the raw packed ECN flags (Bits 0, 1, 2) in the array for the loop to read
            outMetrics[0] = packed & 0x3F;
        }

        return sender;
    }
}