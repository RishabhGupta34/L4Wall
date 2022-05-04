#! /usr/bin/python
from bcc import BPF
import bcc
import sys

program = """
int xdp_pass(struct xdp_md *ctx) {
  bpf_trace_printk("Hello, World!\\n");
  return XDP_PASS;
}
"""

if len(sys.argv) < 2:
    print("USAGE: interface")
    exit()
intf = sys.argv[1]
b = BPF(text=program)
fn = b.load_func("xdp_pass", BPF.XDP)
b.attach_xdp(intf, fn)
try:
    b.trace_print()
except KeyboardInterrupt:
    pass

b.remove_xdp(intf)
