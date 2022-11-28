#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <string.h>


struct counter
{
    __u64 pkts;
    __u64 bytes;
};


struct bpf_map_def SEC("maps") ip_counter_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct counter),
    .max_entries = 10,
};


SEC("xdp_prog")
int xdp_count_tf(struct xdp_md *ctx) {

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;

    if (eth + 1 > data_end) {
        return XDP_PASS;
    }

    if(bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);

    if (iph + 1 > data_end) {
        return XDP_PASS;
    }

    __u32 ip_src = iph->saddr;

    if (!bpf_map_lookup_elem(&ip_counter_map, &ip_src)){
        struct counter ip_cnt;
        memset(&ip_cnt, 0, sizeof(ip_cnt));
        bpf_map_update_elem(&ip_counter_map, &ip_src, &ip_cnt, BPF_NOEXIST);
    }

    struct counter *ip_cnt = bpf_map_lookup_elem(&ip_counter_map, &ip_src);

    if (!ip_cnt){
        return XDP_ABORTED;
    }

    __u64 rx_bytes = data_end - data;

    __sync_fetch_and_add(&ip_cnt->pkts, 1);
    __sync_fetch_and_add(&ip_cnt->bytes, rx_bytes);

    return XDP_PASS;

}


char _license[] SEC("license") = "GPL";
