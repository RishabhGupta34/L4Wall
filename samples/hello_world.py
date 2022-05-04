#! /usr/bin/python
from bcc import BPF
program = """
    int hello(void *ctx){
        u64 uid;
        uid = bpf_get_current_uid_gid();
        bpf_trace_printk("id: %d\\n", uid);
        return 0;
    }
"""

b = BPF(text=program)
b.attach_kprobe(event="sys_clone",fn_name="hello")
b.trace_print()