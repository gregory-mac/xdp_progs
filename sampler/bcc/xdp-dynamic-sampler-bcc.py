from bcc import BPF
import time


bpf_prog = """
#include <uapi/linux/bpf.h>


BPF_PERCPU_ARRAY(counter, u64, 3);
BPF_TABLE_PINNED("array", u32, u32, sampling_factor, 1, "/sys/fs/bpf/sampling_factor");


int sampler(struct xdp_md *ctx)
{
    uint64_t *rx_packets;
    uint64_t *pass;
    uint64_t *drop;
    uint32_t *sample_value;

    uint32_t rx_packets_idx = 0;
    uint32_t pass_idx = 1;
    uint32_t drop_idx = 2;
    uint32_t sample_value_idx = 0;

    rx_packets = counter.lookup(&rx_packets_idx);

    if (rx_packets)
        *rx_packets += 1;

    sample_value = sampling_factor.lookup(&sample_value_idx);

    if (sample_value && rx_packets)
        if (*rx_packets % *sample_value == 0){
            pass = counter.lookup(&pass_idx);
            if (pass)
                *pass += 1;

            return XDP_PASS;
        }

    drop = counter.lookup(&drop_idx);
    if (drop)
        *drop += 1;

    return XDP_DROP;
}
"""


devices = [ "enp35s0f0", "enp35s0f1", "enp193s0f0", "enp193s0f1" ]

bpf = BPF(text=bpf_prog)
func = bpf.load_func("sampler", BPF.XDP)

for dev in devices:
    bpf.attach_xdp(dev, func, BPF.XDP_FLAGS_DRV_MODE)


counter = bpf["counter"]

print("Dumping counters, hit CTRL+C to stop")

while True:
    try:
        for k in counter.keys():
            val = counter.sum(k).value
            print(f"{val}\n")

        time.sleep(1)

    except KeyboardInterrupt:
        print("Detaching XDP program")
        break

for dev in devices:
    bpf.remove_xdp(dev, BPF.XDP_FLAGS_DRV_MODE)
