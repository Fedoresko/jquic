package org.jquic.quic;

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;

public class LinuxEcnSocket implements AutoCloseable {
    private static final MethodHandle quic_receive_ecn;
    private static final MethodHandle quic_receive_ecn_blocking;
    private static final MethodHandle send_to;

    static {
        MethodHandle mh = null;
        MethodHandle mh2 = null;
        MethodHandle mh3 = null;
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

            FunctionDescriptor blockingDescriptor = FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS
            );
            MemorySegment symbolBlocking = lookup.find("quic_receive_ecn_blocking").orElseThrow();
            mh2 = Linker.nativeLinker().downcallHandle(symbolBlocking, blockingDescriptor);

            FunctionDescriptor descForSendTo = FunctionDescriptor.of(
                    ValueLayout.JAVA_LONG,     // Return value: ssize_t
                    ValueLayout.JAVA_INT,      // sockfd
                    ValueLayout.ADDRESS,       // buf (will accept pinned byte[])
                    ValueLayout.JAVA_LONG,     // len
                    ValueLayout.JAVA_INT,      // flags
                    ValueLayout.ADDRESS,       // dest_addr (will accept pinned int[])
                    ValueLayout.JAVA_INT       // addrlen
            );

            symbol = Linker.nativeLinker().defaultLookup().find("sendto")
                    .orElseThrow(() -> new RuntimeException("sendto not found"));

            // critical(true) enables the array pinning feature for downcalls
            mh3 = Linker.nativeLinker().downcallHandle(symbol, descForSendTo, Linker.Option.critical(true));

        } catch (Throwable _) {}
        quic_receive_ecn = mh;
        quic_receive_ecn_blocking = mh2;
        send_to = mh3;
    }

    private final int fd;
    private final Arena socketArena = Arena.ofConfined();
    // nativeMetadata layout (int32_t):
    // 0: port
    // 1: ecnFlags
    // 2: addrLen
    // 3: errno
    // 4-7: remoteAddress (16 bytes)
    private final MemorySegment nativeMetadata = socketArena.allocate(ValueLayout.JAVA_INT, 8);

    public LinuxEcnSocket(int fd) throws Exception {
        if (quic_receive_ecn == null || quic_receive_ecn_blocking == null) {
            throw new Exception("LinuxEcnSocket is not loaded");
        }
        this.fd = fd;
    }

    public SocketAddress receiveBlocking(ByteBuffer dst, int[] outMetrics) throws IOException {
        return receiveImpl(dst, outMetrics, quic_receive_ecn_blocking);
    }

    public SocketAddress receive(ByteBuffer dst, int[] outMetrics) throws IOException {
        return receiveImpl(dst, outMetrics, quic_receive_ecn);
    }

    private SocketAddress receiveImpl(ByteBuffer dst, int[] outMetrics, MethodHandle handle) throws IOException {
        if (dst.isReadOnly()) {
            throw new IllegalArgumentException("Read-only buffer");
        }
        if (outMetrics == null || outMetrics.length < 1) {
            throw new IllegalArgumentException("outMetrics array must be at least size 1");
        }
        if (dst.remaining() <= 0) {
            return null;
        }

        MemorySegment dstSegment = dst.isDirect() 
            ? MemorySegment.ofBuffer(dst)
            : MemorySegment.ofArray(dst.array()).asSlice(dst.arrayOffset() + dst.position(), dst.remaining());

        try {
            int bytesRead = (int) handle.invokeExact(fd, dstSegment, dst.remaining(), nativeMetadata);

            if (bytesRead < 0) {
                int err = nativeMetadata.getAtIndex(ValueLayout.JAVA_INT, 0); // errno is at index 0 when bytesRead < 0
                if (err == 11 || err == 246 /* EAGAIN or EWOULDBLOCK on Linux */) {
                    return null;
                }
                throw new IOException("Native receive error: " + err);
            }

            int port = nativeMetadata.getAtIndex(ValueLayout.JAVA_INT, 0);
            int ecnFlags = nativeMetadata.getAtIndex(ValueLayout.JAVA_INT, 1);
            int addrLen = nativeMetadata.getAtIndex(ValueLayout.JAVA_INT, 2);

            dst.position(dst.position() + bytesRead);
            outMetrics[0] = ecnFlags;


            byte[] ipBytes = new byte[addrLen];
            MemorySegment.copy(nativeMetadata, ValueLayout.JAVA_BYTE, 16, ipBytes, 0, addrLen);

            InetAddress address = InetAddress.getByAddress(ipBytes);

            return new InetSocketAddress(address, port);
        } catch (Throwable t) {
            throw new IOException(t);
        }
    }

    public long send(ByteBuffer buffer, int[] sockaddr) throws IOException {
        // Wrap heap arrays as zero-length MemorySegments to feed the JNI/Panama interface
        // The JVM handles pinning under the hood via critical(true)
        try {
            MemorySegment bufSegment = buffer.isDirect()
                    ? MemorySegment.ofBuffer(buffer)
                    : MemorySegment.ofArray(buffer.array()).asSlice(buffer.arrayOffset() + buffer.position(), buffer.remaining());

            MemorySegment addrSegment = MemorySegment.ofArray(sockaddr);
            return (long) send_to.invokeExact(fd, bufSegment, (long) buffer.remaining(), 0, addrSegment, 16);
        } catch (Throwable t) {
            throw new IOException(t);
        }
    }

    @Override
    public void close() throws Exception {
        socketArena.close();
    }
}