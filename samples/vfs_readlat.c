#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HISTOGRAM(dist);
BPF_HASH(vfs, u32);

int vfs_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 timestamp = bpf_ktime_get_ns();
    vfs.update(&pid,&timestamp);
    return 0;
}

int vfs_exit(struct pt_regs *ctx) {
    u64 delta,*timestamp;

    u32 pid = bpf_get_current_pid_tgid();
    timestamp = vfs.lookup(&pid);

    if(timestamp!=NULL){
        delta = bpf_ktime_get_ns() - *timestamp;
        dist.increment(bpf_log2l(delta/1000));
        vfs.delete(&pid);
    }
    return 0;
}