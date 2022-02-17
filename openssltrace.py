#!/usr/bin/python3
from bcc import BPF
from bcc.utils import printb
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

prog = """
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);
struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

BPF_HASH(currsock, u32, struct sock *);
BPF_HASH(ipv4_hash, u32, struct ipv4_data_t);
BPF_HASH(ipv6_hash, u32, struct ipv6_data_t);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u32 tid = bpf_get_current_pid_tgid();
    // stash the sock ptr for lookup on return
    currsock.update(&tid, &sk);
    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short ipver)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    struct sock **skpp;
    skpp = currsock.lookup(&tid);
    if (skpp == 0) {
        return 0;  // missed entry
    }
    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&tid);
        return 0;
    }
    // pull in details
    struct sock *skp = *skpp;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    
    if (ipver == 4) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = ipver};
        data4.uid = bpf_get_current_uid_gid();
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.saddr = skp->__sk_common.skc_rcv_saddr;
        data4.daddr = skp->__sk_common.skc_daddr;
        data4.lport = lport;
        data4.dport = ntohs(dport);
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_hash.update(&tid, &data4);
    } else /* 6 */ {
        struct ipv6_data_t data6 = {.pid = pid, .ip = ipver};
        data6.uid = bpf_get_current_uid_gid();
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
            skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
            skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.lport = lport;
        data6.dport = ntohs(dport);
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_hash.update(&tid, &data6);
    }
    currsock.delete(&tid);
    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 6);
}

int probe_SSL_connect_accept_enter(struct pt_regs *ctx, void *ssl) {  
    u32 tid = bpf_get_current_pid_tgid();
    struct ipv4_data_t *ipv4p;
    struct ipv6_data_t *ipv6p;
    
    ipv4p = ipv4_hash.lookup(&tid);
    if (ipv4p != NULL) {
        struct ipv4_data_t data;
        bpf_probe_read_kernel(&data, sizeof(data), ipv4p);
        ipv4_events.perf_submit(ctx, &data, sizeof(data));
        ipv4_hash.delete(&tid);
    }

    ipv6p = ipv6_hash.lookup(&tid);
    if (ipv6p != NULL) {
        struct ipv6_data_t data;
        bpf_probe_read_kernel(&data, sizeof(data), ipv6p);
        ipv6_events.perf_submit(ctx, &data, sizeof(data));
        ipv6_hash.delete(&tid);
    }
    
    return 0;
}
"""


def print_ipv4_events(cpu, data, size):
    event = b["ipv4_events"].event(data)
    dest_ip = inet_ntop(AF_INET, pack("I", event.daddr)).encode()
    if event.dport == 443:
        printb(b"%-6d %-12.12s %-2d %-39s %-6d %-39s %-6d" % \
               (event.pid, event.task, event.ip,
                inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
                event.lport, dest_ip, event.dport))


def print_ipv6_events(cpu, data, size):
    event = b["ipv6_events"].event(data)
    dest_ip = inet_ntop(AF_INET6, event.daddr).encode()
    if event.dport == 443:
        printb(b"%-6d %-12.12s %-2d %-39s %-6d %-39s %-6d" % \
               (event.pid, event.task, event.ip,
                inet_ntop(AF_INET6, event.saddr).encode(), event.lport,
                dest_ip, event.dport))


if __name__ == "__main__":
    # Initialize BPF
    b = BPF(text=prog)
    
    # Attach user and kernel probes to the functions that we want to trace
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
    b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")

    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
    b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")

    b.attach_uprobe(name="ssl", sym="SSL_connect", fn_name="probe_SSL_connect_accept_enter")
    b.attach_uprobe(name="ssl", sym="SSL_accept", fn_name="probe_SSL_connect_accept_enter")
    
    # Associate the Python print_ipv*_events functions with the ipv*_events streams
    b["ipv4_events"].open_perf_buffer(print_ipv4_events)
    b["ipv6_events"].open_perf_buffer(print_ipv6_events)

    # Program Header 
    print("Hit Ctrl-C to exit")
    print("%-6s %-12.12s %-2s %-39s %-6s %-39s %-6s" % \
          ("PID", "COMM", "IP", "SADDR", "LPORT", "DADDR", "DPORT"))

    # Main loop
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
