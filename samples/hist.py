#! /usr/bin/python
from bcc import BPF
from time import sleep

program = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HISTOGRAM(dist);

int kprobe__blk_account_io_done(struct pt_regs *ctx, struct request *req) {
    dist.increment(bpf_log2l(req->__data_len/1024));
    return 0;
}
"""

b = BPF(text=program)
try:
    sleep(1000)
except KeyboardInterrupt:
    print("Stopping bpf program")

b["dist"].print_log2_hist("kbytes")
