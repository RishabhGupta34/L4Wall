#! /usr/bin/python
from bcc import BPF

program = """
BPF_HASH(last_time);

int sys_sync_probe(void *ctx) {
  u64 ctime,delta,key=0;
  u64 *timestamp;
  timestamp = last_time.lookup(&key);
  if(timestamp!=NULL){
    ctime = bpf_ktime_get_ns();
    delta = ctime - *timestamp;
    if(delta<1000000000){
        bpf_trace_printk("%d\\n", delta/1000000);
    }
    last_time.update(&key,&ctime);
  }
  return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event="sync", fn_name="sys_sync_probe")
print("Tracing quick sync's")
start = 0
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    if start == 0:
        start = ts
    ts = ts -start
    print("At time %.2f s: Multiple syncs detected, last %s ms ago" % (ts, msg))
