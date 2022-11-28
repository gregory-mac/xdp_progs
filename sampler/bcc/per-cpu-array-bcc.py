from bcc import BPF
from time import sleep


bpf_prog = """
#include <uapi/linux/bpf.h>


BPF_PERCPU_ARRAY(counter, u64, 1);

int sampler(struct xdp_md *ctx)
{
    uint64_t rx_packets = 0;
    uint64_t pass = 0;
    uint64_t drop = 0;

    uint64_t *rx_packets_add;
    uint64_t *pass_add;
    uint64_t *drop_add;

    rx_packets_add = counter.lookup(&rx_packets);
    if (rx_packets_add)
        *rx_packets_add += 1;

    uint64_t sample_value = 100;

    if (*rx_packets_add % sample_value == 0){
        pass_add = counter.lookup(&pass);
        if (pass_add)
            *pass_add += 1;
    	return XDP_PASS;
    }

    drop_add = counter.lookup(&drop);
    if (drop_add)
        *drop_add += 1;
    return XDP_DROP;
}
"""


devices = [ "enp35s0f0", "enp35s0f1", "enp193s0f0", "enp193s0f1" ]

bpf = BPF(text=bpf_prog)

func = bpf.load_func("sampler", BPF.XDP)

for dev in devices:
    bpf.attach_xdp(dev, func, BPF.XDP_FLAGS_DRV_MODE)


counter = bpf.get_table("counter")

print("Dumping counters, hit CTRL+C to stop")

while True:
    try:
        for k in counter.keys():
            print(k)
        time.sleep(1)

    except KeyboardInterrupt:
        print("Unloading XDP progs")
        break

for dev in devices:
    bpf.remove_xdp(dev, BPF.XDP_FLAGS_DRV_MODE)
