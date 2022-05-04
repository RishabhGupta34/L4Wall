#! /usr/bin/python
from bcc import BPF

REQ_WRITE = 1
program = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

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
        bpf_trace_printk("%d %x %d\\n", r->__data_len,r->cmd_flags, delta/1000);
        diskio.delete(&r);
    }
}
"""

b = BPF(text=program)
if BPF.get_kprobe_functions(b'blk_start_request'):
    b.attach_kprobe(event="blk_start_request", fn_name="diskio_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="diskio_start")
b.attach_kprobe(event="blk_account_io_done", fn_name="diskio_complete")
print("Tracing disk io's")
start = 0
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    if start == 0:
        start = ts
    ts = ts -start
    print("At time %.2f s: Disk io completed, details: %s" % (ts, msg))
