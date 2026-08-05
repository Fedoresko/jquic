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
#define MAX_BATCH_RX 64

// Size of control buffer for a single packet to capture IPv4 TOS or IPv6 TCLASS
#define CMSG_BUF_SIZE CMSG_SPACE(sizeof(int))


#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>

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

int32_t send_batch_fast(int32_t fd, void** data_ptrs, int32_t* lengths, void** sockaddr_ptrs, int32_t count) {
    if (count <= 0 || count > 128) return 0; // Prevent stack overflow boundary

    struct mmsghdr msg_vec[128];
    struct iovec io_vec[128];

    for (int32_t i = 0; i < count; i++) {
        // Point the iovec directly to your distinct memory segments
        io_vec[i].iov_base = data_ptrs[i];
        io_vec[i].iov_len = lengths[i];

        // Format the outer message wrapper
        memset(&msg_vec[i], 0, sizeof(struct mmsghdr));
        msg_vec[i].msg_hdr.msg_name = sockaddr_ptrs[i];
        msg_vec[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
        msg_vec[i].msg_hdr.msg_iov = &io_vec[i];
        msg_vec[i].msg_hdr.msg_iovlen = 1; // 1 segment per packet
    }

    // Single native system call execution
    int32_t res = sendmmsg(fd, msg_vec, count, 0);

    if (res < 0) {
        int error_code = errno;
        fprintf(stderr, "Fatal error on system call: %s (code %d)\n",
                strerror(error_code), error_code);
    }

    return res;
}

// Structure matching the layout required to return packet information to Java
// Out metadata format per packet (10 elements total = 40 bytes per packet slot):
//: bytes_read, [1]: port, [2]: ecn_flags, [3]: addr_len, [4-7]: remote_addr (16 bytes), [8]: status/errno
int32_t quic_receive_batch_ecn(int32_t fd, void** data_ptrs, int32_t max_len, int32_t* out_metadata, int32_t max_count) {
    if (max_count <= 0 || max_count > MAX_BATCH_RX || data_ptrs == NULL || out_metadata == NULL) {
        return -1;
    }

    struct mmsghdr msg_vec[MAX_BATCH_RX];
    struct iovec io_vec[MAX_BATCH_RX];
    struct sockaddr_storage peer_addrs[MAX_BATCH_RX];
    char cmsg_bufs[MAX_BATCH_RX][CMSG_BUF_SIZE];

    // 1. Prepare structures for the entire batch
    for (int32_t i = 0; i < max_count; i++) {
        io_vec[i].iov_base = data_ptrs[i];
        io_vec[i].iov_len = (size_t)max_len;

        memset(&msg_vec[i], 0, sizeof(struct mmsghdr));
        msg_vec[i].msg_hdr.msg_name = &peer_addrs[i];
        msg_vec[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
        msg_vec[i].msg_hdr.msg_iov = &io_vec[i];
        msg_vec[i].msg_hdr.msg_iovlen = 1;

        // Assign distinct control buffer per packet to isolate ECN bits
        memset(cmsg_bufs[i], 0, CMSG_BUF_SIZE);
        msg_vec[i].msg_hdr.msg_control = cmsg_bufs[i];
        msg_vec[i].msg_hdr.msg_controllen = CMSG_BUF_SIZE;
    }

    // 2. Perform the non-blocking batched kernel read
    int32_t received = recvmmsg(fd, msg_vec, (unsigned int)max_count, MSG_DONTWAIT, NULL);

    if (received < 0) {
        out_metadata[0] = errno; // First element for errno on error
        return -1;
    }

    // 3. Process every read packet and serialize its metadata into a flattened 1D array for Java
    for (int32_t i = 0; i < received; i++) {
        // Calculate the base pointer index for this packet slot in out_metadata (Stride of 10)
        int32_t base_idx = i * 10;

        int32_t bytes_read = (int32_t)msg_vec[i].msg_len;
        int32_t ecn_flags = 0;
        int32_t port = 0;
        int32_t addr_len = 0;
        void* addr_ptr = NULL;

        // Parse ECN metadata out of this specific packet's control stream
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg_vec[i].msg_hdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg_vec[i].msg_hdr, cmsg)) {
            // Support both IPv4 (IP_TOS) and IPv6 (IPV6_TCLASS) targets
            if ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS) ||
                (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS)) {

                unsigned char tos = *(unsigned char *)CMSG_DATA(cmsg);
                unsigned char ecn_bits = tos & 0x03;

                if (ecn_bits == 3)      ecn_flags |= (1 << 0); // CE (Congestion Experienced)
                else if (ecn_bits == 1) ecn_flags |= (1 << 1); // ECT(1)
                else if (ecn_bits == 2) ecn_flags |= (1 << 2); // ECT(0)
                break;
            }
        }

        // Parse network addresses safely
        if (peer_addrs[i].ss_family == AF_INET) {
            struct sockaddr_in *addr4 = (struct sockaddr_in *)&peer_addrs[i];
            port = ntohs(addr4->sin_port);
            addr_len = 4;
            addr_ptr = &addr4->sin_addr.s_addr;
        } else if (peer_addrs[i].ss_family == AF_INET6) {
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&peer_addrs[i];
            port = ntohs(addr6->sin6_port);
            addr_len = 16;
            addr_ptr = &addr6->sin6_addr.s6_addr;
        }

        // Write sequentially to the flattened Java metadata memory slot
        out_metadata[base_idx + 0] = bytes_read;
        out_metadata[base_idx + 1] = port;
        out_metadata[base_idx + 2] = ecn_flags;
        out_metadata[base_idx + 3] = addr_len;
        out_metadata[base_idx + 8] = 0; // Error status code: success

        // Zero out the remote address buffer before copying to prevent dirty leak
        memset(&out_metadata[base_idx + 4], 0, 16);
        if (addr_ptr) {
            memcpy(&out_metadata[base_idx + 4], addr_ptr, addr_len);
        }
    }

    return received; // Return total packets successfully parsed to Java
}

int32_t quic_receive_batch_ecn_blocking(int32_t fd, void** data_ptrs, int32_t max_len, int32_t* out_metadata, int32_t max_count) {
    // 1. Try a fast non-blocking read first
    int32_t bytes = quic_receive_batch_ecn(fd, data_ptrs, max_len, out_metadata, max_count);

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
        return quic_receive_batch_ecn(fd, data_ptrs, max_len, out_metadata, max_count);
    }

    return bytes;
}