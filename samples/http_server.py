from __future__ import print_function
from bcc import BPF, USDT
import sys

if len(sys.argv) < 2:
    print("USAGE: nodejs_http_server PID")
    exit()
pid = sys.argv[1]
bpf_text = """
    #include <uapi/linux/ptrace.h>
    int do_trace(struct pt_regs *ctx){
        uint64_t addr;
        char path[128] = {};
        bpf_usdt_readarg(6, ctx, &addr);
        bpf_probe_read_user(&path, sizeof(path), (void *)addr);
        bpf_trace_printk("path: %s",path);
        return 0;
    }
    u = USDT(pid=int(pid))
    u.enable_probe(probe="http__server__request", fn_name="do_trace")
"""