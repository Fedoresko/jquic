package org.fmalyshev.quic;

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;

public class LinuxEcnSocket {
    private static final MethodHandle quic_receive_ecn;

    static {
        MethodHandle mh = null;
        try {
            System.loadLibrary("quic_ecn");
            SymbolLookup lookup = SymbolLookup.loaderLookup();
            MemorySegment symbol = lookup.find("quic_receive_ecn").orElseThrow();
            
            FunctionDescriptor descriptor = FunctionDescriptor.of(
                ValueLayout.JAVA_INT,    // return bytes_read
                ValueLayout.JAVA_INT,    // fd
                ValueLayout.ADDRESS,     // buf
                ValueLayout.JAVA_INT,    // length
                ValueLayout.ADDRESS      // out_metadata
            );
            
            mh = Linker.nativeLinker().downcallHandle(symbol, descriptor, Linker.Option.critical(true));
        } catch (Throwable t) {
        }
        quic_receive_ecn = mh;
    }

    private final int fd;
    // metadataBuffer layout (int32_t):
    // 0: port
    // 1: ecnFlags
    // 2: addrLen
    // 3: errno
    // 4-7: remoteAddress (16 bytes)
    private final int[] metadataBuffer = new int[8];

    public LinuxEcnSocket(int fd) throws Exception {
        if (quic_receive_ecn == null) {
            throw new Exception("LinuxEcnSocket is not loaded");
        }
        this.fd = fd;
    }

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

        MemorySegment dstSegment = dst.isDirect() 
            ? MemorySegment.ofBuffer(dst).asSlice(position, remaining)
            : MemorySegment.ofArray(dst.array()).asSlice(dst.arrayOffset() + position, remaining);
        
        MemorySegment metadataSegment = MemorySegment.ofArray(metadataBuffer);

        try {
            int bytesRead = (int) quic_receive_ecn.invokeExact(fd, dstSegment, remaining, metadataSegment);

            if (bytesRead < 0) {
                int err = metadataBuffer[0]; // errno is at index 0 when bytesRead < 0
                if (err == 11 || err == 246 /* EAGAIN or EWOULDBLOCK on Linux */) {
                    return null;
                }
                throw new IOException("Native receive error: " + err);
            }

            dst.position(position + bytesRead);
            int port = metadataBuffer[0];
            int ecnFlags = metadataBuffer[1];
            int addrLen = metadataBuffer[2];
            // metadataBuffer[3] is errno (0)
            outMetrics[0] = ecnFlags;

            byte[] addrBytes = new byte[addrLen];
            // Copy IP address from metadataBuffer (starts at index 4)
            // Each int is 4 bytes.
            ByteBuffer bb = ByteBuffer.allocate(16).order(java.nio.ByteOrder.nativeOrder());
            bb.asIntBuffer().put(metadataBuffer, 4, 4);
            System.arraycopy(bb.array(), 0, addrBytes, 0, addrLen);
            
            InetAddress address = InetAddress.getByAddress(addrBytes);

            return new InetSocketAddress(address, port);
        } catch (IOException e) {
            throw e;
        } catch (Throwable t) {
            throw new IOException(t);
        }
    }
}