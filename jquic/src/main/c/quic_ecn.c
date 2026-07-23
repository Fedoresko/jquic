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

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <poll.h>
#include <errno.h>

int32_t quic_receive_ecn(int32_t fd, void *buf, int32_t length, int32_t *out_metadata) {
    if (buf == NULL || out_metadata == NULL) {
        return -1;
    }

    struct iovec iov = { .iov_base = buf, .iov_len = length };
    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    struct sockaddr_storage peer_addr;

    struct msghdr msg = {
        .msg_name = &peer_addr,
        .msg_namelen = sizeof(peer_addr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf)
    };

    ssize_t bytes_read = recvmsg(fd, &msg, 0);

    if (bytes_read < 0) {
        out_metadata[0] = errno; // First element for errno on error
        return -1;
    }

    int ecn_flags = 0;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS) {
            unsigned char tos = *(unsigned char *)CMSG_DATA(cmsg);
            unsigned char ecn_bits = tos & 0x03;
            if (ecn_bits == 3) ecn_flags |= (1 << 0);
            else if (ecn_bits == 1) ecn_flags |= (1 << 1);
            else if (ecn_bits == 2) ecn_flags |= (1 << 2);
            break;
        }
    }

    int32_t addr_len = 0;
    int32_t port = 0;
    void *addr_ptr = NULL;
    if (peer_addr.ss_family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&peer_addr;
        port = ntohs(addr4->sin_port);
        addr_len = 4;
        addr_ptr = &addr4->sin_addr.s_addr;
    } else if (peer_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&peer_addr;
        port = ntohs(addr6->sin6_port);
        addr_len = 16;
        addr_ptr = &addr6->sin6_addr.s6_addr;
    }

    // Pack into out_metadata (int32_t array)
    // 0: port
    // 1: ecn_flags
    // 2: addr_len
    // 3: errno (0 on success)
    // 4-7: remote_addr (16 bytes)
    out_metadata[0] = port;
    out_metadata[1] = ecn_flags;
    out_metadata[2] = addr_len;
    out_metadata[3] = 0; 
    if (addr_ptr) {
        memcpy(&out_metadata[4], addr_ptr, addr_len);
    }

    return (int32_t)bytes_read;
}

// A blocking wrapper that uses your exact function
int32_t quic_receive_ecn_blocking(int32_t fd, void *buf, int32_t length, int32_t *out_metadata) {
    // 1. Try a fast non-blocking read first
    int32_t bytes = quic_receive_ecn(fd, buf, length, out_metadata);

    // 2. If no data, use poll() to wait indefinitely at 0% CPU
    if (bytes < 0 && (out_metadata[0] == EAGAIN || out_metadata[0] == EWOULDBLOCK)) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };

        // This blocks the thread natively until UDP data hits the NIC
        int ret = poll(&pfd, 1, 10);
        if (ret <= 0) {
            out_metadata[0] = errno;
            return -1; // Handle poll error or interrupt
        }

        // 3. Data is guaranteed ready, run your exact code again
        return quic_receive_ecn(fd, buf, length, out_metadata);
    }

    return bytes;
}
