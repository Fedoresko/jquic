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

#define SOCKET_PATH "/var/run/quic_loader.sock"
#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024

static struct bpf_object *obj = NULL;
static int sock_map_fd = -1;
static int acc_map_fd = -1;
static int prog_fd = -1;
static int server_fd = -1;
static volatile sig_atomic_t running = 1;

void cleanup() {
    if (server_fd >= 0) close(server_fd);
    unlink(SOCKET_PATH);
    if (obj) bpf_object__close(obj);
    printf("Daemon shutting down...\n");
}

void signal_handler(int sig) {
    running = 0;
}

int load_bpf_program() {
    // Clean up older stale pins if they exist
    unlink("/sys/fs/bpf/quic_sock_map");
    unlink("/sys/fs/bpf/acceptor_map");
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
    struct bpf_map *acc_map = bpf_object__find_map_by_name(obj, "acceptor_map");
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "quic_sk_steer");

    if (!sock_map || !acc_map || !prog) {
        fprintf(stderr, "Failed to locate maps or program section\n");
        return -1;
    }

    // Pin maps and program to make them globally reachable via path strings
    if (bpf_map__pin(sock_map, "/sys/fs/bpf/quic_sock_map") != 0) {
        fprintf(stderr, "Failed to pin sock_map\n");
        return -1;
    }
    if (bpf_map__pin(acc_map, "/sys/fs/bpf/acceptor_map") != 0) {
        fprintf(stderr, "Failed to pin acceptor_map\n");
        return -1;
    }

    sock_map_fd = bpf_map__fd(sock_map);
    acc_map_fd = bpf_map__fd(acc_map);
    prog_fd = bpf_program__fd(prog);

    if (bpf_program__pin(prog, "/sys/fs/bpf/quic_steer_prog") != 0) {
        fprintf(stderr, "Failed to pin program\n");
        return -1;
    }

    printf("eBPF Program loaded and pinned successfully!\n");
    return 0;
}

int create_unix_socket() {
    struct sockaddr_un addr;

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket creation failed");
        return -1;
    }

    // Remove old socket file if exists
    unlink(SOCKET_PATH);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        close(server_fd);
        return -1;
    }

    // Make socket accessible to non-root users in socket group
    chmod(SOCKET_PATH, 0666);

    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("listen failed");
        close(server_fd);
        return -1;
    }

    printf("Unix socket listening at %s\n", SOCKET_PATH);
    return 0;
}

void handle_attach_command(int client_fd, char *cmd) {
    int socket_fd;
    char prog_path[256];

    if (sscanf(cmd, "ATTACH %d %s", &socket_fd, prog_path) != 2) {
        write(client_fd, "ERROR: Invalid ATTACH syntax\n", 29);
        return;
    }

    if (bpf_prog_attach(prog_fd, socket_fd, BPF_SK_REUSEPORT_SELECT, 0) != 0) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "ERROR: Failed to attach program: %s\n", strerror(errno));
        write(client_fd, err_msg, strlen(err_msg));
        return;
    }

    write(client_fd, "OK\n", 3);
}

void handle_update_map_command(int client_fd, char *cmd) {
    char map_name[256];
    unsigned int key;
    unsigned long long value;

    if (sscanf(cmd, "UPDATE_MAP %s %u %llu", map_name, &key, &value) != 3) {
        write(client_fd, "ERROR: Invalid UPDATE_MAP syntax\n", 33);
        return;
    }

    int map_fd = -1;
    if (strcmp(map_name, "acceptor_map") == 0) {
        map_fd = acc_map_fd;
    } else if (strcmp(map_name, "quic_sock_map") == 0) {
        map_fd = sock_map_fd;
    } else {
        write(client_fd, "ERROR: Unknown map name\n", 24);
        return;
    }

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "ERROR: Failed to update map: %s\n", strerror(errno));
        write(client_fd, err_msg, strlen(err_msg));
        return;
    }

    write(client_fd, "OK\n", 3);
}

void handle_register_selector_command(int client_fd, char *cmd) {
    unsigned int index;
    unsigned long long socket_fd;

    if (sscanf(cmd, "REGISTER_SELECTOR %u %llu", &index, &socket_fd) != 2) {
        write(client_fd, "ERROR: Invalid REGISTER_SELECTOR syntax\n", 40);
        return;
    }

    if (bpf_map_update_elem(sock_map_fd, &index, &socket_fd, BPF_ANY) != 0) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "ERROR: Failed to register selector: %s\n", strerror(errno));
        write(client_fd, err_msg, strlen(err_msg));
        return;
    }

    write(client_fd, "OK\n", 3);
}

void handle_delete_map_command(int client_fd, char *cmd) {
    char map_name[256];
    unsigned long long key;

    if (sscanf(cmd, "DELETE_MAP %s %llu", map_name, &key) != 2) {
        write(client_fd, "ERROR: Invalid DELETE_MAP syntax\n", 33);
        return;
    }

    int map_fd = -1;
    if (strcmp(map_name, "acceptor_map") == 0) {
        map_fd = acc_map_fd;
    } else if (strcmp(map_name, "/sys/fs/bpf/quic_sock_map") == 0 ||
               strcmp(map_name, "quic_sock_map") == 0) {
        map_fd = sock_map_fd;
    } else {
        write(client_fd, "ERROR: Unknown map name\n", 24);
        return;
    }

    if (bpf_map_delete_elem(map_fd, &key) != 0) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "ERROR: Failed to delete map entry: %s\n", strerror(errno));
        write(client_fd, err_msg, strlen(err_msg));
        return;
    }

    write(client_fd, "OK\n", 3);
}

void handle_clear_map_command(int client_fd, char *cmd) {
    char map_name[256];

    if (sscanf(cmd, "CLEAR_MAP %s", map_name) != 1) {
        write(client_fd, "ERROR: Invalid CLEAR_MAP syntax\n", 32);
        return;
    }

    int map_fd = -1;
    if (strcmp(map_name, "/sys/fs/bpf/quic_sock_map") == 0 ||
        strcmp(map_name, "quic_sock_map") == 0) {
        map_fd = sock_map_fd;
    } else if (strcmp(map_name, "acceptor_map") == 0) {
        map_fd = acc_map_fd;
    } else {
        write(client_fd, "ERROR: Unknown map name\n", 24);
        return;
    }

    // Iterate all keys and delete them one by one
    unsigned long long key, next_key;
    int errors = 0;
    int ret = bpf_map_get_next_key(map_fd, NULL, &next_key);
    while (ret == 0) {
        key = next_key;
        ret = bpf_map_get_next_key(map_fd, &key, &next_key);
        if (bpf_map_delete_elem(map_fd, &key) != 0) {
            errors++;
        }
    }

    if (errors > 0) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "ERROR: Failed to delete %d map entries\n", errors);
        write(client_fd, err_msg, strlen(err_msg));
        return;
    }

    write(client_fd, "OK\n", 3);
}

void handle_client(int client_fd) {
    char buffer[BUFFER_SIZE];
    ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);

    if (n <= 0) {
        close(client_fd);
        return;
    }

    buffer[n] = '\0';

    // Remove trailing newline
    if (buffer[n-1] == '\n') buffer[n-1] = '\0';

    printf("Received command: %s\n", buffer);

    if (strncmp(buffer, "ATTACH ", 7) == 0) {
        handle_attach_command(client_fd, buffer);
    } else if (strncmp(buffer, "UPDATE_MAP ", 11) == 0) {
        handle_update_map_command(client_fd, buffer);
    } else if (strncmp(buffer, "REGISTER_SELECTOR ", 18) == 0) {
        handle_register_selector_command(client_fd, buffer);
    } else if (strncmp(buffer, "DELETE_MAP ", 11) == 0) {
        handle_delete_map_command(client_fd, buffer);
    } else if (strncmp(buffer, "CLEAR_MAP ", 10) == 0) {
        handle_clear_map_command(client_fd, buffer);
    } else {
        write(client_fd, "ERROR: Unknown command\n", 23);
    }

    close(client_fd);
}

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Check if running as root
    if (geteuid() != 0) {
        fprintf(stderr, "This daemon must run as root\n");
        return 1;
    }

    if (load_bpf_program() != 0) {
        return 1;
    }

    if (create_unix_socket() != 0) {
        cleanup();
        return 1;
    }

    printf("QUIC Loader Daemon started successfully\n");

    while (running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);

        struct timeval tv = {1, 0}; // 1 second timeout
        int ret = select(server_fd + 1, &readfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("select failed");
            break;
        }

        if (ret == 0) continue; // Timeout

        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept failed");
            continue;
        }

        handle_client(client_fd);
    }

    cleanup();
    return 0;
}