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
package org.jquic.quic.linux;

import org.jquic.quic.QuicDatagramChannel;
import org.jquic.quic.SelectorThread;
import org.jquic.quic.buffers.PoolBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

public class LinuxEcnSocket implements AutoCloseable {
    private static final MethodHandle quic_receive_ecn;
    private static final MethodHandle quic_receive_ecn_blocking;
    private static final MethodHandle quic_receive_batch_ecn;
    private static final MethodHandle quic_receive_batch_ecn_blocking;
    private static final MethodHandle send_batch_fast;
    private static final MethodHandle send_to;
    private static final Logger log = LoggerFactory.getLogger(LinuxEcnSocket.class);

    static {
        MethodHandle mh = null;
        MethodHandle mh2 = null;
        MethodHandle mh_batch = null;
        MethodHandle mh_batch_blocking = null;
        MethodHandle mh_send_batch = null;
        MethodHandle mh3 = null;
        try {
            NativeUtil.loadLib("libquic_ecn");
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
                    ValueLayout.JAVA_INT
            );
            MemorySegment symbolBlocking = lookup.find("quic_receive_ecn_blocking").orElseThrow();
            mh2 = Linker.nativeLinker().downcallHandle(symbolBlocking, blockingDescriptor);

            FunctionDescriptor batchDescriptor = FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,    // return received count
                    ValueLayout.JAVA_INT,    // fd
                    ValueLayout.ADDRESS,     // data_ptrs (void**)
                    ValueLayout.JAVA_INT,    // max_len
                    ValueLayout.ADDRESS,     // out_metadata (int*)
                    ValueLayout.JAVA_INT     // max_count
            );
            mh_batch = Linker.nativeLinker().downcallHandle(
                    lookup.find("quic_receive_batch_ecn").orElseThrow(),
                    batchDescriptor,
                    Linker.Option.critical(true)
            );
            mh_batch_blocking = Linker.nativeLinker().downcallHandle(
                    lookup.find("quic_receive_batch_ecn_blocking").orElseThrow(),
                    batchDescriptor
            );

            mh_send_batch = Linker.nativeLinker().downcallHandle(
                    lookup.find("send_batch_fast").orElseThrow(),
                    FunctionDescriptor.of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, // data_ptrs
                            ValueLayout.ADDRESS, // lengths (Assuming it should be a pointer to int32_t)
                            ValueLayout.ADDRESS, // sockaddr_ptrs
                            ValueLayout.JAVA_INT
                    ),
                    Linker.Option.critical(true)
            );

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

        } catch (Throwable e) {}
        quic_receive_ecn = mh;
        quic_receive_ecn_blocking = mh2;
        quic_receive_batch_ecn = mh_batch;
        quic_receive_batch_ecn_blocking = mh_batch_blocking;
        send_batch_fast = mh_send_batch;
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
    private final MemorySegment batchMetadata = socketArena.allocate(ValueLayout.JAVA_INT, 10 * 64);
    private final MemorySegment batchAddrs = socketArena.allocate(JAVA_BYTE, 16 * 128);
    private final MemorySegment dataPtrsRcv = socketArena.allocate(ValueLayout.ADDRESS, 64);
    private final MemorySegment dataPtrs = socketArena.allocate(ValueLayout.ADDRESS, 128);
    private final MemorySegment lengthsSegment = socketArena.allocate(ValueLayout.JAVA_INT, 128);
    private final MemorySegment sockaddrPtrs = socketArena.allocate(ValueLayout.ADDRESS, 128);


    public LinuxEcnSocket(int fd) throws Exception {
        if (quic_receive_ecn == null || quic_receive_ecn_blocking == null) {
            throw new Exception("LinuxEcnSocket is not loaded");
        }
        this.fd = fd;
    }

    /**
     * Build sockaddr_in struct in native mem
     * @param ip - ip in network byte order
     * @param port - port (standard byte order)
     */
    public void buildSockAddr(byte[] ip, int port, int idx) {
        int pos = idx * 16;

        // Byte 0-1: sin_family (AF_INET = 2). Native Linux host order.
        batchAddrs.set(JAVA_SHORT, pos, (short) 2);

        // Byte 2-3: sin_port. Explicitly Big Endian (Network byte order).
        batchAddrs.set(JAVA_SHORT, pos + 2, Short.reverseBytes( (short) port));

        // Byte 4-7: sin_addr.
        batchAddrs.set(JAVA_BYTE, pos + 4, ip[0]);
        batchAddrs.set(JAVA_BYTE, pos + 5, ip[1]);
        batchAddrs.set(JAVA_BYTE, pos + 6, ip[2]);
        batchAddrs.set(JAVA_BYTE, pos + 7, ip[3]);
    }

    public List<QuicDatagramChannel.ReceivedPacket> receiveBatchBlocking(PoolBuffer[] buffers) throws IOException {
        return receiveBatchImpl(buffers, quic_receive_batch_ecn_blocking);
    }

    public List<QuicDatagramChannel.ReceivedPacket> receiveBatch(PoolBuffer[] buffers) throws IOException {
        return receiveBatchImpl(buffers, quic_receive_batch_ecn);
    }

    private List<QuicDatagramChannel.ReceivedPacket> receiveBatchImpl(PoolBuffer[] buffers, MethodHandle handle) throws IOException {
        int maxCount = buffers.length;
        try {
            int maxLen = 0;
            for (int i = 0; i < maxCount; i++) {
                ByteBuffer buf = buffers[i].buf().clear();
                MemorySegment seg = buf.isDirect()
                        ? MemorySegment.ofBuffer(buf)
                        : MemorySegment.ofArray(buf.array()).asSlice(buf.arrayOffset() + buf.position(), buf.remaining());
                dataPtrsRcv.setAtIndex(ValueLayout.ADDRESS, i, seg);
                maxLen = Math.max(maxLen, buf.remaining());
            }

            int received = (int) handle.invokeExact(fd, dataPtrsRcv, maxLen, batchMetadata, maxCount);

            if (received < 0) {
                int err = batchMetadata.getAtIndex(ValueLayout.JAVA_INT, 0);
                if (err == 11 || err == 246) {
                    return List.of();
                }
                throw new IOException("Native receive batch error: " + err);
            }

            List<QuicDatagramChannel.ReceivedPacket> results = new ArrayList<>(received);
            for (int i = 0; i < received; i++) {
                int baseIdx = i * 10;
                int bytesRead = batchMetadata.getAtIndex(ValueLayout.JAVA_INT, baseIdx);
                int port = batchMetadata.getAtIndex(ValueLayout.JAVA_INT, baseIdx + 1);
                int ecnFlags = batchMetadata.getAtIndex(ValueLayout.JAVA_INT, baseIdx + 2);
                int addrLen = batchMetadata.getAtIndex(ValueLayout.JAVA_INT, baseIdx + 3);

                PoolBuffer pb = buffers[i];
                ByteBuffer buf = pb.buf();
                buf.limit(buf.position() + bytesRead);

                byte[] ipBytes = new byte[addrLen];
                MemorySegment.copy(batchMetadata, ValueLayout.JAVA_BYTE, (long) (baseIdx + 4) * 4, ipBytes, 0, addrLen);
                InetAddress address = InetAddress.getByAddress(ipBytes);
                SocketAddress sender = new InetSocketAddress(address, port);

                log.info("Packet {} in batch pos: {} len: {} addr: {} port: {}", i, buf.position(), bytesRead, address, port);

                results.add(new QuicDatagramChannel.ReceivedPacket(pb, sender, ecnFlags));
            }

            return results;
        } catch (Throwable t) {
            throw new IOException(t);
        }
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

            log.warn("Packet pos: {} len: {} addr: {} port: {}", dst.position(), bytesRead, address, port);

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

    public int sendBatch(Collection<SelectorThread.PacketToSend> data) throws IOException {
        try {
            int size = data.size();
            int i = 0;
            for (SelectorThread.PacketToSend entry : data) {
                ByteBuffer buf = entry.poolBuffer().buf();
                MemorySegment bufSeg = buf.isDirect()
                        ? MemorySegment.ofBuffer(buf)
                        : MemorySegment.ofArray(buf.array()).asSlice(buf.arrayOffset() + buf.position(), buf.remaining());
                dataPtrs.setAtIndex(ValueLayout.ADDRESS, i, bufSeg);
                lengthsSegment.setAtIndex(ValueLayout.JAVA_INT, i, buf.remaining());

                InetSocketAddress isa = (InetSocketAddress) entry.socketAddress();
                buildSockAddr(isa.getAddress().getAddress(), isa.getPort(), i);
                sockaddrPtrs.setAtIndex(ValueLayout.ADDRESS, i, batchAddrs.asSlice(i * 16L, 16));
                i++;
            }
            return (int) send_batch_fast.invokeExact(fd, dataPtrs, lengthsSegment, sockaddrPtrs, size);
        } catch (Throwable t) {
            throw new IOException(t);
        }
    }

    @Override
    public void close() throws Exception {
        socketArena.close();
    }
}
