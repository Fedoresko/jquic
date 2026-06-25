package org.fmalyshev.quic;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;

/**
 * Client for communicating with the quic_loader daemon via Unix domain socket.
 * The daemon must be running with root privileges to handle eBPF operations.
 * All operations are no-ops if the daemon is not available.
 */
public class BpfDaemonClient {
    private static final Logger logger = LoggerFactory.getLogger(BpfDaemonClient.class);
    private static final String SOCKET_PATH = "/var/run/quic_loader.sock";
    private static final String PROG_PATH = "/sys/fs/bpf/quic_steer_prog";
    private static final String MAP_SOCK_PATH = "/sys/fs/bpf/quic_sock_map";
    private static boolean daemonAvailable = false;
    private static boolean initialized = false;

    /**
     * Initializes the BPF daemon client by checking daemon availability.
     * Should be called once at application startup.
     * Subsequent calls will not re-check availability.
     */
    public static void initialize() {
        if (initialized) {
            return;
        }
        
        try {
            String response = sendCommand("PING");
            daemonAvailable = response.equals("OK") || response.equals("PONG");
            
            if (daemonAvailable) {
                logger.info("eBPF daemon detected - kernel-space packet routing enabled");
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    try {
                        clearEbpfMap();
                    } catch (Exception e) {
                        logger.warn("Failed to clear eBPF map during shutdown: {}", e.getMessage());
                    }
                }, "ebpf-shutdown-cleaner"));
            } else {
                logger.warn("eBPF daemon responded with unexpected reply - using Java-space routing");
            }
        } catch (IOException e) {
            daemonAvailable = false;
            logger.info("eBPF daemon not available - using Java-space packet routing");
        }
        
        initialized = true;
    }

    /**
     * Attaches the eBPF program to a socket file descriptor.
     * No-op if daemon is not available.
     *
     * @param socketFd The socket file descriptor to attach the program to
     * @param progPath The path to the pinned eBPF program (not used in current impl, kept for compatibility)
     * @throws IOException if communication with daemon fails
     * @throws BpfDaemonException if the daemon returns an error
     */
    private static void attachEbpfToSocket(int socketFd, String progPath) throws IOException, BpfDaemonException {
        String command = String.format("ATTACH %d %s", socketFd, progPath);
        String response = sendCommand(command);

        if (!response.equals("OK")) {
            throw new BpfDaemonException("Failed to attach eBPF program: " + response);
        }
    }

    /**
     * Updates an eBPF map with a key-value pair.
     * No-op if daemon is not available.
     *
     * @param key The key as an integer
     * @param value The value as a long (file descriptor or other data)
     * @throws IOException if communication with daemon fails
     * @throws BpfDaemonException if the daemon returns an error
     */
    public static void updateEbpfMap(int key, long value) throws IOException, BpfDaemonException {
        if (!daemonAvailable) {
            return;
        }

        updateEbpfMapImpl(MAP_SOCK_PATH, key, value);
    }

    /**
     * Clears all entries from the quic_sock_map.
     * Intended to be called during graceful shutdown to ensure no stale CID mappings
     * remain in the eBPF map after the application stops.
     * No-op if daemon is not available.
     *
     * @throws IOException if communication with daemon fails
     * @throws BpfDaemonException if the daemon returns an error
     */
    public static void clearEbpfMap() throws IOException, BpfDaemonException {
        if (!daemonAvailable) {
            return;
        }

        String command = String.format("CLEAR_MAP %s", MAP_SOCK_PATH);
        String response = sendCommand(command);

        if (!response.equals("OK")) {
            throw new BpfDaemonException("Failed to clear eBPF map: " + response);
        }

        logger.info("Cleared all entries from eBPF sock map");
    }

    /**
     * Deletes an entry from the eBPF map.
     * No-op if daemon is not available.
     *
     * @param selectorId The selector thread ID
     * @param connectionId The connection ID to remove
     * @throws IOException if communication with daemon fails
     * @throws BpfDaemonException if the daemon returns an error
     */
    public static void deleteEbpfMap(int selectorId, long connectionId) throws IOException, BpfDaemonException {
        if (!daemonAvailable) {
            return;
        }

        String command = String.format("DELETE_MAP %s %d", MAP_SOCK_PATH, connectionId);
        String response = sendCommand(command);

        if (!response.equals("OK")) {
            throw new BpfDaemonException("Failed to delete map entry: " + response);
        }

        logger.debug("Deleted CID {} from eBPF map (selector {})", connectionId, selectorId);
    }

    private static void updateEbpfMapImpl(String mapName, int key, long value) throws IOException, BpfDaemonException {
        String command = String.format("UPDATE_MAP %s %d %d", mapName, key, value);
        String response = sendCommand(command);

        if (!response.equals("OK")) {
            throw new BpfDaemonException("Failed to update map: " + response);
        }
    }

    /**
     * Registers a selector socket in the quic_sock_map.
     * No-op if daemon is not available.
     *
     * @param index The index/key for this selector
     * @param selectorChannel The socket file descriptor
     * @throws IOException if communication with daemon fails
     * @throws BpfDaemonException if the daemon returns an error
     */
    public static void registerSelector(int index, DatagramChannel selectorChannel) throws Exception {
        if (!daemonAvailable) {
            return;
        }

        int selectorFd = getNativeFd(selectorChannel);

        String command = String.format("REGISTER_SELECTOR %d %d", index, selectorFd);
        String response = sendCommand(command);

        if (!response.equals("OK")) {
            throw new BpfDaemonException("Failed to register selector: " + response);
        }
    }

    /**
     * Cross-version reflection helper to extract native File Descriptors.
     * Compatible with Java 8, 11, and 17 LTS runtimes on Linux platforms.
     */
    private static int getNativeFd(DatagramChannel channel) throws NoSuchFieldException, IllegalAccessException {
        Field fdField = channel.getClass().getDeclaredField("fd");
        fdField.setAccessible(true);
        Object fdObj = fdField.get(channel);

        Field intField = fdObj.getClass().getDeclaredField("fd");
        intField.setAccessible(true);
        return intField.getInt(fdObj);
    }

    /**
     * Sends a command to the daemon and returns the response.
     *
     * @param command The command string to send
     * @return The response from the daemon
     * @throws IOException if communication fails
     */
    private static String sendCommand(String command) throws IOException {
        UnixDomainSocketAddress address = UnixDomainSocketAddress.of(Path.of(SOCKET_PATH));

        try (SocketChannel channel = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            channel.connect(address);

            // Send command
            PrintWriter writer = new PrintWriter(Channels.newOutputStream(channel), true);
            writer.println(command);
            writer.flush();

            // Read response
            BufferedReader reader = new BufferedReader(new InputStreamReader(Channels.newInputStream(channel)));
            String response = reader.readLine();

            if (response == null) {
                throw new IOException("No response from daemon");
            }

            return response.trim();
        }
    }

    static void registerAcceptor(DatagramChannel acceptorChannel) throws NoSuchFieldException, IllegalAccessException, IOException, BpfDaemonException {
        if (!daemonAvailable) {
            return;
        }

        int acceptorFd = getNativeFd(acceptorChannel);
        // Link Acceptor Socket FD into Index 0 of the pinned acceptor_map
        updateEbpfMapImpl("acceptor_map", 0, acceptorFd);

        // Bind the loaded eBPF socket program to the Acceptor Socket group
        attachEbpfToSocket(acceptorFd, PROG_PATH);
    }

    /**
     * Exception thrown when the daemon reports an error.
     */
    public static class BpfDaemonException extends Exception {
        public BpfDaemonException(String message) {
            super(message);
        }
    }
}
