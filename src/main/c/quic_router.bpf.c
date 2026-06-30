#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define FIXED_CID_LEN 8

/* Maps CID to socket index for routing */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u32); // Socket index
} quic_sock_map SEC(".maps");

/* Reuseport sockarray holding all sockets (acceptor + selectors) */
struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} sockarray_map SEC(".maps");

const char hex_chars[] = "0123456789abcdef";

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define byte_array_to_hex_lookup(bytes, byte_len, hex_string) for (int i = 0; i < (byte_len); i++) { hex_string[i * 2] = hex_chars[(bytes[i] >> 4) & 0x0F]; hex_string[i * 2 + 1] = hex_chars[bytes[i] & 0x0F]; } hex_string[byte_len * 2] = '\0'

// Define a reusable inline helper function at the top of your file
#define redirect_to_acceptor(ctx) { bpf_sk_select_reuseport(ctx, &sockarray_map, &default_thread_index, 0); if (++cont == 1) return SK_PASS; }

SEC("sk_reuseport")
int quic_sk_steer(struct sk_reuseport_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 default_thread_index = 0;

    if (data + 9 > data_end) redirect_to_acceptor(ctx);

    __u8 *quic_payload = (__u8 *) (data + 8);

    __u8 first_byte = *quic_payload;
    __u8 *dcid_start;
    __u8 dcid_len;

    // Parse DCID location based on header type (RFC 9000)
    int isLong = 0;
    if (first_byte & 0x80) {
        isLong = 1;
        // LONG HEADER: Version(4) + DCID Len(1) + DCID + SCID Len(1) + SCID
        if ((void *)(quic_payload + 6) > data_end) {
            redirect_to_acceptor(ctx);
        }

        dcid_len = quic_payload[5]; // DCID length at byte 5
        dcid_start = quic_payload + 6; // DCID starts at byte 6
    } else {
        // SHORT HEADER: DCID starts at byte 1 (no length field)
        dcid_len = FIXED_CID_LEN; // Short headers use fixed-length DCID
        dcid_start = quic_payload + 1;
    }

    __u32 selected_socket = 0;
    __u64 cid_key = 0;
    // Verify DCID length matches expected length (8 bytes)
    if (dcid_len == FIXED_CID_LEN && (void *)(dcid_start + FIXED_CID_LEN) <= data_end) {
        cid_key = __builtin_bswap64(*(__u64 *)dcid_start);

        __u32 *sock_idx = bpf_map_lookup_elem(&quic_sock_map, &cid_key);
        if (sock_idx) {
            selected_socket = *sock_idx;
        } else {
            bpf_printk("Selector not found!");
        }
    }

    int ret = bpf_sk_select_reuseport(ctx, &sockarray_map, &selected_socket, 0);

    if (ret < 0) {
        bpf_printk("bpf_sk_select_reuseport failed with error: %d\n", ret);
    }
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";