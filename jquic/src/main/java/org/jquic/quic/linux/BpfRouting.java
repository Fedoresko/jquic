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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
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

    private static final MethodHandle bpf_update_map_i;
    private static final MethodHandle bpf_update_map_l;
    private static final MethodHandle bpf_delete_map_i;
    private static final MethodHandle bpf_delete_map_l;
    private static final MethodHandle bpf_check_map;
    private static final MethodHandle bpf_attach_socket;
    private static final MethodHandle bpf_set_affinity;

    static {
        MethodHandle update_i = null;
        MethodHandle update_l = null;
        MethodHandle delete_i = null;
        MethodHandle delete_l = null;
        MethodHandle check = null;
        MethodHandle attach = null;
        MethodHandle affinity = null;
        try {
            NativeUtil.loadLib("libjavabpf.so");
            SymbolLookup lookup = SymbolLookup.loaderLookup();
            Linker linker = Linker.nativeLinker();

            update_i = linker.downcallHandle(
                lookup.find("bpf_update_map_i").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT),
                Linker.Option.critical(true)
            );
            update_l = linker.downcallHandle(
                lookup.find("bpf_update_map_l").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT),
                Linker.Option.critical(true)
            );
            delete_i = linker.downcallHandle(
                lookup.find("bpf_delete_map_i").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT),
                Linker.Option.critical(true)
            );
            delete_l = linker.downcallHandle(
                lookup.find("bpf_delete_map_l").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
                Linker.Option.critical(true)
            );
            check = linker.downcallHandle(
                lookup.find("bpf_check_map").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
            );
            attach = linker.downcallHandle(
                lookup.find("bpf_attach_socket").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
            );
            affinity = linker.downcallHandle(
                lookup.find("bpf_set_affinity").orElseThrow(),
                //ValueLayout.JAVA_INT,
                FunctionDescriptor.ofVoid( ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
            );

            initialized = true;
        } catch (Throwable e) {
            initialized = false;
        }
        bpf_update_map_i = update_i;
        bpf_update_map_l = update_l;
        bpf_delete_map_i = delete_i;
        bpf_delete_map_l = delete_l;
        bpf_check_map = check;
        bpf_attach_socket = attach;
        bpf_set_affinity = affinity;
    }

    private static void setDedicatedCpu(int pid, int cpu) {
        long[] mask = new long[cpu / 64 + 1];
        mask[cpu / 64] = 1L << cpu;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment maskSegment = arena.allocateFrom(ValueLayout.JAVA_LONG, mask);
            bpf_set_affinity.invokeExact(pid, maskSegment, (int) mask.length);
        } catch (Throwable t) {
            logger.error("Failed to set CPU affinity", t);
        }
    }

    private static void registerSocketInBpf(int fd, int mapIndex) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pathSegment = arena.allocateFrom(BPF_MAP_SOCKARRAY);
            int result = (int) bpf_update_map_i.invokeExact(pathSegment, mapIndex, fd);
            if (result < 0) {
                throw new RuntimeException("Failed to register runtime socket in eBPF map. Error code: " + result);
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    private static void updateRouteMapping(long cid, int selectorId) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pathSegment = arena.allocateFrom(BPF_MAP_ROUTES);
            int result = (int) bpf_update_map_l.invokeExact(pathSegment, cid, selectorId);
            if (result < 0) {
                throw new RuntimeException("Failed to register BPF update route mapping. Error code: " + result);
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    private static void removeRouteMapping(long cid) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pathSegment = arena.allocateFrom(BPF_MAP_ROUTES);
            int result = (int) bpf_delete_map_l.invokeExact(pathSegment, cid);
            if (result < 0) {
                throw new RuntimeException("Failed to remove BPF route mapping. Error code: " + result);
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    private static void attachEBpfToSocket(String progPath, int socketFd) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pathSegment = arena.allocateFrom(progPath);
            int result = (int) bpf_attach_socket.invokeExact(pathSegment, socketFd);
            if (result < 0) {
                throw new RuntimeException("Failed to attach eBPF program. Error code: " + result);
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Throwable t) {
            throw new RuntimeException(t);
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

            try (Arena arena = Arena.ofConfined()) {
                MemorySegment routesPath = arena.allocateFrom(BPF_MAP_ROUTES);
                MemorySegment sockarrayPath = arena.allocateFrom(BPF_MAP_SOCKARRAY);
                
                isReady = (int) bpf_check_map.invokeExact(routesPath) == 0 &&
                        (int) bpf_check_map.invokeExact(sockarrayPath) == 0;
            } catch (Throwable t) {
                isReady = false;
                logger.error("Failed to check BPF maps", t);
            }

            logger.info("Available routing: " + isReady);
        }
    }

    /**
     * Updates an eBPF map with a cid-selectorId pair.
     * No-op if daemon is not available.
     *
     * @param cid        The cid as an integer
     * @param selectorId The selectorId as a long (file descriptor or other data)
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

        int selectorFd = NativeUtil.getNativeFd(selectorChannel);

        registerSocketInBpf(selectorFd, index);
    }

    public static void registerAcceptor(DatagramChannel acceptorChannel) throws NoSuchFieldException, IllegalAccessException {
        if (!isReady) {
            return;
        }
        int acceptorFd = NativeUtil.getNativeFd(acceptorChannel);
        attachEBpfToSocket(BPF_PROG_PATH, acceptorFd);
        // Bind the loaded eBPF socket program to the Acceptor Socket group
        registerSocketInBpf(acceptorFd, 0);
    }
}

