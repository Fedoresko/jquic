package org.fmalyshev.quic;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InaccessibleObjectException;
import java.nio.channels.DatagramChannel;

/**
 * Client for communicating with the quic_loader daemon via Unix domain socket.
 * The daemon must be running with root privileges to handle eBPF operations.
 * All operations are no-ops if the daemon is not available.
 */
public class BpfRouting {
    private static final Logger logger = LoggerFactory.getLogger(BpfRouting.class);
    public static final String BPF_MAP_ROUTES = "/sys/fs/bpf/quic_sock_map";
    public static final String BPF_MAP_SOCKARRAY = "/sys/fs/bpf/sockarray_map";
    public static final String BPF_PROG_PATH = "/sys/fs/bpf/quic_steer_prog";
    private static boolean isReady = false;
    private static boolean initialized;

    static {
        try {
            System.loadLibrary("javabpf");
            initialized = true;
        } catch (UnsatisfiedLinkError e) {
            initialized = false;
        }
    }

    // Native declaration matching the Linux bpf_map_update_elem system call
    private static native int nativeUpdateBpfMapI(String mapPath, int key, int socketFd);

    private static native int nativeUpdateBpfMapL(String mapPath, long key, int socketFd);

    private static native int nativeDeleteFromBpfMapI(String mapPath, int key);

    private static native int nativeDeleteFromBpfMapL(String mapPath, long key);

    private static native int checkBpfMap(String mapPath);

    private static native int attachEBpfToSocket(String progPath, int socketFd);

    private static native int setAffinity(int pid, long[] mask);

    private static void setDedicatedCpu(int pid, int cpu) {
        long[] mask = new long[cpu / 64 + 1];
        mask[cpu / 64] = 1L << cpu;
        setAffinity(pid, mask);
    }

    private static void registerSocketInBpf(int fd, int mapIndex) {
        // 3. Insert Java's own FD directly into the pinned BPF map
        int result = nativeUpdateBpfMapI(BPF_MAP_SOCKARRAY, mapIndex, fd);
        if (result < 0) {
            throw new RuntimeException("Failed to register runtime socket in eBPF map. Error code: " + result);
        }
    }

    private static void updateRouteMapping(long cid, int selectorId) {
        // 3. Insert Java's own FD directly into the pinned BPF map
        int result = nativeUpdateBpfMapL(BPF_MAP_ROUTES, cid, selectorId);
        if (result < 0) {
            throw new RuntimeException("Failed to register BPF update route mapping. Error code: " + result);
        }
    }

    private static void removeRouteMapping(long cid) {
        int result = nativeDeleteFromBpfMapL(BPF_MAP_ROUTES, cid);
        if (result < 0) {
            throw new RuntimeException("Failed to remove BPF route mapping. Error code: " + result);
        }
    }

    /**
     * Initializes the BPF daemon client by checking daemon availability.
     * Should be called once at application startup.
     * Subsequent calls will not re-check availability.
     */
    public static void initialize() {
        if (initialized) {
            logger.info("Initializing BPF routing...");

            isReady = checkBpfMap(BPF_MAP_ROUTES) == 0 &&
                    checkBpfMap(BPF_MAP_SOCKARRAY) == 0;

            logger.info("Available routing: " + isReady);
        }
    }

    /**
     * Updates an eBPF map with a cid-selectorId pair.
     * No-op if daemon is not available.
     *
     * @param cid        The cid as an integer
     * @param selectorId The selectorId as a long (file descriptor or other data)
     * @throws IOException if communication with daemon fails
     */
    public static void updateRouting(long cid, int selectorId) {
        if (!isReady) {
            return;
        }

        updateRouteMapping(cid, selectorId);
    }

    /**
     * Deletes an entry from the eBPF map.
     * No-op if daemon is not available.
     *
     * @param cid The connection ID to remove
     */
    public static void evictRoute(long cid) {
        if (!isReady) {
            return;
        }

        removeRouteMapping(cid);
    }

    /**
     * Registers a selector socket in the sockarray_map.
     * No-op if daemon is not available.
     *
     * @param index           The index/key for this selector in the sockarray
     * @param selectorChannel The socket file descriptor
     * @throws IOException if communication with daemon fails
     */
    public static void registerSelector(int index, DatagramChannel selectorChannel) throws Exception {
        if (!isReady) {
            return;
        }

        int processors = Runtime.getRuntime().availableProcessors();
        setDedicatedCpu(index, 1 % processors);

        int selectorFd = getNativeFd(selectorChannel);

        registerSocketInBpf(selectorFd, index);
    }

    static void registerAcceptor(DatagramChannel acceptorChannel) throws NoSuchFieldException, IllegalAccessException {
        if (!isReady) {
            return;
        }
        int acceptorFd = getNativeFd(acceptorChannel);
        attachEBpfToSocket(BPF_PROG_PATH, acceptorFd);
        // Bind the loaded eBPF socket program to the Acceptor Socket group
        registerSocketInBpf(acceptorFd, 0);
    }


    /**
     * Cross-version reflection helper to extract native File Descriptors.
     * Compatible with Java 8, 11, and 17 LTS runtimes on Linux platforms.
     * <p>
     * Note: For Java 9+, you must add JVM arguments:
     * --add-opens java.base/sun.nio.ch=ALL-UNNAMED --add-opens java.base/java.io=ALL-UNNAMED
     */
    private static int getNativeFd(DatagramChannel channel) throws NoSuchFieldException, IllegalAccessException {
        try {
            Field fdField = channel.getClass().getDeclaredField("fd");
            fdField.setAccessible(true);
            Object fdObj = fdField.get(channel);

            Field intField = fdObj.getClass().getDeclaredField("fd");
            intField.setAccessible(true);
            return intField.getInt(fdObj);
        } catch (InaccessibleObjectException e) {
            throw new IllegalStateException(
                    "Cannot access file descriptor. Add JVM arguments: " +
                            "--add-opens java.base/sun.nio.ch=ALL-UNNAMED --add-opens java.base/java.io=ALL-UNNAMED", e);
        }
    }
}
