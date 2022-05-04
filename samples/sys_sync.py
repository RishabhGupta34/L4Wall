#! /usr/bin/python
from bcc import BPF

program = """
int sys_sync_probe(void *ctx) {
  bpf_trace_printk("Hello, World!\\n");
  return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event="sys_sync", fn_name="sys_sync_probe")
b.trace_print()
