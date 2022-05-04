#! /usr/bin/python
from bcc import BPF

program = """
int clone(void *ctx) {
  bpf_trace_printk("Hello, World!\\n");
  return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="clone")
print("%-18s %-3s %-16s %-16s %-6s %s" % ("TIME(s)", "CPU", "COMM", "FLAGS", "PID", "MESSAGE"))
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.5f %-4d %-16s %-16s %-6d %s" % (ts,cpu, task, flags,pid, msg))