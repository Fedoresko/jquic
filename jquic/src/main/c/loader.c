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
// Compile with: gcc loader.c -lbpf -o quic_loader
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <netinet/in.h>

#define SOCKET_PATH "/var/run/quic_loader.sock"
#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024

static struct bpf_object *obj = NULL;
static int sock_map_fd = -1;
static int sockarray_map_fd = -1;
static struct bpf_map * sockarray_map = NULL;
static int prog_fd = -1;
static int server_fd = -1;
static volatile sig_atomic_t running = 1;

int load_bpf_program() {
    // Ensure BPF filesystem is mounted
    if (system("mount | grep -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf") != 0) {
        fprintf(stderr, "Warning: Failed to ensure BPF FS is mounted\n");
    }

    // Clean up older stale pins if they exist
    unlink("/sys/fs/bpf/quic_sock_map");
    unlink("/sys/fs/bpf/sockarray_map");
    unlink("/sys/fs/bpf/quic_steer_prog");

    // Load ELF object
    obj = bpf_object__open_file("quic_router.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open eBPF object file\n");
        return -1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load eBPF object into kernel\n");
        return -1;
    }

    // Locate the maps within the compiled object
    struct bpf_map *sock_map = bpf_object__find_map_by_name(obj, "quic_sock_map");
    sockarray_map = bpf_object__find_map_by_name(obj, "sockarray_map");
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "quic_sk_steer");

    if (!sock_map || !sockarray_map || !prog) {
        fprintf(stderr, "Failed to locate maps or program section\n");
        return -1;
    }

    // Pin maps and program to make them globally reachable via path strings
    if (bpf_map__pin(sock_map, "/sys/fs/bpf/quic_sock_map") != 0) {
        fprintf(stderr, "Failed to pin sock_map\n");
        return -1;
    }
    if (bpf_map__pin(sockarray_map, "/sys/fs/bpf/sockarray_map") != 0) {
        return -1;
    }

    sock_map_fd = bpf_map__fd(sock_map);
    sockarray_map_fd = bpf_map__fd(sockarray_map);
    prog_fd = bpf_program__fd(prog);

    if (bpf_program__pin(prog, "/sys/fs/bpf/quic_steer_prog") != 0) {
        fprintf(stderr, "Failed to pin program\n");
        return -1;
    }


    if (chmod("/sys/fs/bpf/quic_sock_map", 0666) < 0) {
        fprintf(stderr, "Failed to chmod quic_sock_map\n");
        return -1;
    }
    if (chmod("/sys/fs/bpf/sockarray_map", 0666) < 0) {
        fprintf(stderr, "Failed to chmod sockarray_map\n");
        return -1;
    }
    if (chmod("/sys/fs/bpf/quic_steer_prog", 0666) < 0) {
        fprintf(stderr, "Failed to chmod quic_steer_prog\n");
        return -1;
    }

    printf("eBPF Program loaded and pinned successfully!\n");
    return 0;
}

int main() {
    // Check if running as root
    if (geteuid() != 0) {
        fprintf(stderr, "This tool must run as root\n");
        return 1;
    }

    if (load_bpf_program() != 0) {
        return 1;
    }

    return 0;
}
