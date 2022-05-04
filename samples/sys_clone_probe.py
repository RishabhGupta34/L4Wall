#! /usr/bin/python
from bcc import BPF

program = """
int sys_clone_probe(void *ctx) {
  bpf_trace_printk("Hello, World!\\n");
  return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event="sys_clone", fn_name="sys_clone_probe")
b.trace_print()
