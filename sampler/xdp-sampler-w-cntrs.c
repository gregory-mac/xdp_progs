#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


struct counter
{
    __u64 rx_packets;
    __u64 pass;
    __u64 drop;
};


struct bpf_map_def SEC("maps") counter = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counter),
    .max_entries = 1,
};


SEC("xdp_sampler")
int sampler(struct xdp_md *ctx)
{
    __u32 counter_idx = 0;
    struct counter *cnt = bpf_map_lookup_elem(&counter, &counter_idx);

    if (!cnt)
    {
        return XDP_ABORTED;
    }

    __sync_fetch_and_add(&cnt->rx_packets, 1);

    __u64 sample_value = 10;

    if (cnt->rx_packets % sample_value == 0){
        __sync_fetch_and_add(&cnt->pass, 1);
    	return XDP_PASS;
    }

    __sync_fetch_and_add(&cnt->drop, 1);
    return XDP_DROP;
}


char _license[] SEC("license") = "GPL";
