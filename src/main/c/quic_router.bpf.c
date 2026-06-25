#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define FIXED_CID_LEN 8

/* Maps an 8-byte CID key directly to a specific Selector socket */
struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u64); // Holds socket file descriptor reference
} quic_sock_map SEC(".maps");

/* Fallback index for the Acceptor Thread (Index 0 in the array) */
struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} acceptor_map SEC(".maps");

SEC("sk_reuseport/quic_steer")
int quic_sk_steer(struct sk_reuseport_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return SK_DROP;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return SK_DROP;
    if (ip->protocol != IPPROTO_UDP) return SK_PASS;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return SK_DROP;

    __u8 *quic_payload = (__u8 *)(udp + 1);
    if ((void *)(quic_payload + 1) > data_end) return SK_DROP;

    __u8 first_byte = *quic_payload;

    // 1. EVALUATE HEADER FORM
    if (first_byte & 0x80) {
        /* LONG HEADER DETECTED: Route directly to the Acceptor Thread */
        __u32 acceptor_idx = 0;
        long ret = bpf_sk_select_reuseport(ctx, &acceptor_map, &acceptor_idx, 0);
        if (ret == 0) return SK_PASS;
        return SK_DROP;
    } else {
        /* SHORT HEADER DETECTED: Parse fixed 8-byte CID starting at Byte 1 */
        if ((void *)(quic_payload + 1 + FIXED_CID_LEN) > data_end) {
            return SK_DROP;
        }

        // Read the 8 bytes directly into a 64-bit primitive key
        __u64 cid_key;
        __builtin_memcpy(&cid_key, quic_payload + 1, FIXED_CID_LEN);

        /* 2. ROUTE TO TARGET SELECTOR THREAD */
        long ret = bpf_sk_select_reuseport(ctx, &quic_sock_map, &cid_key, 0);
        if (ret == 0) {
            return SK_PASS;
        }

        // Fallback to Acceptor if mapping is missing
        __u32 acceptor_idx = 0;
        bpf_sk_select_reuseport(ctx, &acceptor_map, &acceptor_idx, 0);
        return SK_PASS;
    }
}

char _license[] SEC("license") = "GPL";