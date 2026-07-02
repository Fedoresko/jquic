package org.fmalyshev.quic;

import org.fmalyshev.quic.buffers.BufferPool;
import org.fmalyshev.quic.buffers.PoolBuffer;
import org.fmalyshev.quic.buffers.RootPoolBuffer;
import org.fmalyshev.quic.streamapi.QuicStreamEngine;
import org.fmalyshev.quic.streamapi.impl.QuicStreamEngineImpl;
import org.jctools.queues.MpscArrayQueue;
import org.jctools.queues.MpscGrowableArrayQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketOption;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.ArrayList;
import java.util.Set;

public class QuicEngine {
    private static final int PORT = 4433;

    // Constant for the number of processing workers
    public static final int SELECTOR_COUNT = 4;
    public static final int WORKER_COUNT = 4;

    // Singleton stream engine for managing all connections
    private static QuicStreamEngineImpl streamEngineInternal;

    private static final Logger logger = LoggerFactory.getLogger(QuicEngine.class);
    private static ArrayList<Thread> selectorThreads;
    private static Thread acceptorThread;

    private static BufferPool bufferPool = new BufferPool();
    /**
     * Gets the static QuicStreamEngineInternal instance.
     * This is used by QuicConnection to register/unregister connections.
     *
     * @return The singleton stream engine instance, or null if not initialized
     */
    static QuicStreamEngineImpl getStreamEngineInternal() {
        return streamEngineInternal;
    }

    public static QuicStreamEngine getStreamEngine() {
        return streamEngineInternal;
    }

    public static BufferPool getPool() {
        return bufferPool;
    }

    private static DatagramChannel createSocketWithReusePort() throws IOException {
        DatagramChannel channel = DatagramChannel.open();
        channel.configureBlocking(true);

        Set<SocketOption<?>> options = channel.supportedOptions();

        if (options.contains(StandardSocketOptions.SO_REUSEADDR) ) {
            channel.setOption(StandardSocketOptions.SO_REUSEADDR, true);
        } else {
            logger.info("SO_REUSEADDR is not supported by this JVM");
        }

        if (options.contains(StandardSocketOptions.SO_REUSEPORT) ) {
            channel.setOption(StandardSocketOptions.SO_REUSEPORT, true);
        } else {
            logger.info("SO_REUSEPORT is not supported by this JVM");
        }

        channel.bind(new InetSocketAddress(PORT));
        return channel;
    }

    public static void init() throws Exception {
        // Initialize BPF daemon client (checks availability and caches result)
        BpfRouting.initialize();
        QuicCrypto.initKeystore();

        // Create QuicStreamEngineInternal singleton
        // This needs QuicStreamEngine which should be created first
        streamEngineInternal = new QuicStreamEngineImpl(WORKER_COUNT);
        streamEngineInternal.start();
        logger.info("QuicStreamEngineInternal singleton created and started");

        // Create shared CID-to-Selector mapping
        java.util.concurrent.ConcurrentHashMap<Long, Integer> cidToSelectorMap =
                new java.util.concurrent.ConcurrentHashMap<Long, Integer>();

        // 1. Initialize the Master Acceptor Thread
        DatagramChannel acceptorChannel = createSocketWithReusePort();

        BpfRouting.registerAcceptor(acceptorChannel);

        AcceptorThread acceptor = new AcceptorThread(acceptorChannel, cidToSelectorMap);

        selectorThreads = new ArrayList<>();
        // 2. Initialize Worker Selector Threads
        SelectorThread[] selectors = new SelectorThread[SELECTOR_COUNT];
        for (int selectorThreadId = 0; selectorThreadId < selectors.length; selectorThreadId++) {
            DatagramChannel selectorChannel = createSocketWithReusePort();

            // Register selector socket in the eBPF map
            BpfRouting.registerSelector(selectorThreadId+1, selectorChannel);

            selectors[selectorThreadId] = new SelectorThread(selectorThreadId, selectorChannel,
                    cidToSelectorMap);

            Thread thread = new Thread(selectors[selectorThreadId], "Selector-Thread-" + selectorThreadId);
            thread.start();
            selectorThreads.add(thread);
        }

        // Wire up acceptor with selector references for packet forwarding
        acceptor.setSelectors(selectors);

        acceptorThread = new Thread(acceptor, "Acceptor-Thread");
        acceptorThread.start();

        logger.info("QUIC Multiplex Server actively listening on port {}", PORT);
    }

    public static void stop() throws Exception {
        streamEngineInternal.shutdown();
        selectorThreads.forEach(Thread::interrupt);
        acceptorThread.interrupt();
    }
}