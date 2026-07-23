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
#define _GNU_SOURCE

#include <jni.h>
#include <errno.h>
#include <sched.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

static int my_libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static int getMapFd(const char *path) {
    // 1. Open the pinned map via its global path string
    int map_fd = bpf_obj_get(path);
    return map_fd;
}

int bpf_set_affinity(int pid, const long *mask_ptr, int mask_len) {
    cpu_set_t set;
    CPU_ZERO(&set);

    if (mask_len > (int)(sizeof(set) / sizeof(long))) {
        mask_len = sizeof(set) / sizeof(long);
    }

    for (int i = 0; i < mask_len; i++) {
        ((long*)&set)[i] = mask_ptr[i];
    }

    return sched_setaffinity((pid_t)pid, sizeof(set), &set) == 0 ? 0 : errno;
}

int bpf_attach_socket(const char *prog_path, int socket_fd) {
    libbpf_set_print(my_libbpf_print_fn);

    int prog_fd = getMapFd(prog_path);
    if (prog_fd < 0) return -1;

    // Pass the eBPF program descriptor straight to the Linux kernel socket level
    int result = setsockopt(socket_fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd));

    return result; // Returns 0 on success, or -1 on failure
}

int bpf_update_map_i(const char *map_path, int key, int socket_fd) {
    int map_fd = getMapFd(map_path);
    if (map_fd < 0) return -1;
    __u32 bpf_key = (__u32)key;
    int err = bpf_map_update_elem(map_fd, &bpf_key, &socket_fd, BPF_ANY);
    return err;
}

int bpf_update_map_l(const char *map_path, long key, int socket_fd) {
    int map_fd = getMapFd(map_path);
    if (map_fd < 0) return -1;
    __u64 bpf_key = (__u64)key;
    int err = bpf_map_update_elem(map_fd, &bpf_key, &socket_fd, BPF_ANY);
    return err;
}

int bpf_delete_map_l(const char *map_path, long key) {
    int map_fd = getMapFd(map_path);
    if (map_fd < 0) return -1;
    __u64 bpf_key = (__u64)key;
    int err = bpf_map_delete_elem(map_fd, &bpf_key);
    return err;
}

int bpf_delete_map_i(const char *map_path, int key) {
    int map_fd = getMapFd(map_path);
    if (map_fd < 0) return -1;
    __u32 bpf_key = (__u32)key;
    int err = bpf_map_delete_elem(map_fd, &bpf_key);
    return err;
}

int bpf_check_map(const char *map_path) {
    int map_fd = getMapFd(map_path);
    if (map_fd >= 0) {
        return 0;
    }
    return -1;
}


