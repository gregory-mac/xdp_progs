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
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counter),
    .max_entries = 1,
};


struct bpf_map_def SEC("maps") sample = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};


static __always_inline __u64 get_sample_value()
{
    __u32 sample_idx = 0;
    __u64 *elem = bpf_map_lookup_elem(&sample, &sample_idx);
    
    if (!elem)
    {
        return XDP_ABORTED;
    }

    return *elem;
}


SEC("xdp_prog")
int sampler(struct xdp_md *ctx)
{
    __u32 counter_idx = 0;
    struct counter *cnt = bpf_map_lookup_elem(&counter, &counter_idx);

    if (!cnt)
    {
        return XDP_ABORTED;
    }

    cnt->rx_packets++;

    __u64 sample_value = get_sample_value();

    if (cnt->rx_packets % sample_value == 0){
        cnt->pass++;
    	return XDP_PASS;
    }

    cnt->drop++;
    return XDP_DROP;
}


char _license[] SEC("license") = "GPL";