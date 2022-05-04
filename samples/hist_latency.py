#! /usr/bin/python
from bcc import BPF
from time import sleep

program = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HISTOGRAM(dist);
BPF_HASH(diskio, struct request *);

void diskio_start(struct pt_regs *ctx, struct request *r) {
    u64 timestamp = bpf_ktime_get_ns();
    diskio.update(&r, &timestamp);
}

void diskio_complete(struct pt_regs *ctx, struct request *r) {
    u64 delta,*timestamp;
    timestamp = diskio.lookup(&r);
    if(timestamp!=NULL){
        delta = bpf_ktime_get_ns() - *timestamp;
        dist.increment(bpf_log2l(delta));
        diskio.delete(&r);
    }
}
"""

b = BPF(text=program)
if BPF.get_kprobe_functions(b'blk_start_request'):
    b.attach_kprobe(event="blk_start_request", fn_name="diskio_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="diskio_start")
b.attach_kprobe(event="blk_account_io_done", fn_name="diskio_complete")
try:
    sleep(120)
except KeyboardInterrupt:
    print("Stopping bpf program")

print("Stopping bpf program")
b["dist"].print_log2_hist("latency")
