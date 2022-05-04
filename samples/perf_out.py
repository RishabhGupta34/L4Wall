#! /usr/bin/python
from bcc import BPF

program = """
#include <linux/sched.h>

struct data_t{
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 count;
};

struct key_command{
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(command_count, struct key_command);

int hello(struct pt_regs *ctx) {
    u64 zero = 0;
    char command[TASK_COMM_LEN];
    struct data_t data = {};
    struct key_command key = {};
    u64 *count;
    
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    
    count = command_count.lookup_or_try_init(&key,&zero);
    if(count!=NULL){
        data.count = *count + 1;
        command_count.increment(key);
    }
    
    events.perf_submit(ctx,&data,sizeof(data));
    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event="__x64_sys_clone", fn_name="hello")
print("Tracing clone's")
print("%-18s %-16s %-6s %s %-18s" % ("TIME(s)", "COMM", "PID", "MESSAGE", "COUNT"))
start = 0
def print_event(cpu,data,size):
    global start
    event = b["events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts-start))/1000000000
    print("%-18.9f %-16s %-6d %s %-6d" % (time_s, event.comm, event.pid, "Hellooo", event.count))

b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()
