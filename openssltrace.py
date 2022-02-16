#!/usr/bin/python3
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6, gethostbyaddr
from struct import pack, unpack

prog = """
#include <linux/ptrace.h>
#include <net/sock.h>
#include <linux/socket.h>

struct ipv4_data_t {
    u32 pid;
    u32 uid;
    u32 daddr;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);
struct ipv6_data_t {
    u32 pid;
    u32 uid;
    unsigned __int128 daddr;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

BPF_HASH(currsock, u32, struct sockaddr *);

int syscall__connect(struct pt_regs *ctx, int sockfd, struct sockaddr *addrp, int addrlen) {
    struct sockaddr_in addr;

    u32 fd = sockfd;
    if (addrp->sa_family == AF_INET) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = pid_tgid;
        currsock.update(&pid, &addrp);
    }
    
    return 0;
}

int probe_SSL_connect_enter(struct pt_regs *ctx, void *ssl) {  
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    struct sockaddr **addrpp;
    
    addrpp = currsock.lookup(&pid);
    if (addrpp == NULL)
        return 0;

    if ((*addrpp)->sa_family == AF_INET) {
        struct sockaddr_in *addrp_v4;
        addrp_v4 = (struct sockaddr_in *) *addrpp;
        if (addrp_v4 == NULL)
            return 0;

        struct ipv4_data_t data = {.pid = pid};
        data.uid = bpf_get_current_uid_gid();
        data.daddr = addrp_v4->sin_addr.s_addr;
        data.dport = addrp_v4->sin_port;
        bpf_get_current_comm(&data.task, sizeof(data.task));       
        ipv4_events.perf_submit(ctx, &data, sizeof(data));
        currsock.delete(&pid);
    }
    else if ((*addrpp)->sa_family == AF_INET6) {
        struct sockaddr_in6 *addrp_v6;
        addrp_v6 = (struct sockaddr_in6 *) *addrpp;
        if (addrp_v6 == NULL)
            return 0;

        struct ipv6_data_t data = {.pid = pid};
        data.uid = bpf_get_current_uid_gid();
        bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), addrp_v6->sin6_addr.s6_addr);
        data.dport = addrp_v6->sin6_port;
        bpf_get_current_comm(&data.task, sizeof(data.task));       
        ipv6_events.perf_submit(ctx, &data, sizeof(data));
        currsock.delete(&pid);
    }
    
    return 0;
}
"""


def dec_to_ipv6(dec):
  max_int64 = 0xFFFFFFFFFFFFFFFF
  return inet_ntop(AF_INET6, pack('!QQ', dec >> 64, dec & max_int64))


def dec_to_ipv4(dec):
  return inet_ntop(AF_INET, pack('I', dec))


def dec_to_port(dec):
  return unpack('!H', pack('H', dec))[0]


def addr_to_domain_name(addr):
  return gethostbyaddr(addr)[0]


def print_ipv4_events(cpu, data, size):
    print_ipv6_events(cpu, data, size, AF_INET)


def print_ipv6_events(cpu, data, size):
    print_ipv6_events(cpu, data, size, AF_INET6)


def print_ipv6_events(cpu, data, size, ipver):
    if (ipver == AF_INET):
        event = b["ipv4_events"].event(data)
        addr = dec_to_ipv4(event.daddr)
    elif (ipver == AF_INET6):
        event = b["ipv6_events"].event(data)
        addr = dec_to_ipv6(event.daddr)
    else:
        raise "IP version error"
    
    task = event.task.decode()
    port = dec_to_port(event.dport)
    if (port == 443):
        try:
            domain_name = addr_to_domain_name(addr)
        except:
            domain_name = ""
        print("%-5s %-9s %s:%s %s" % (event.pid, task, addr, port, domain_name))


def main():
    print("%-5s %-9s %-21s" % ("PID", "COMM", "DST"))
    
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()


if __name__ == "__main__":
    global b
    b = BPF(text=prog)
    b.attach_uprobe(name="ssl", sym="SSL_connect", fn_name="probe_SSL_connect_enter")
    b.attach_kprobe(event=b.get_syscall_fnname("connect"), fn_name="syscall__connect")
    b["ipv4_events"].open_perf_buffer(print_ipv4_events)
    b["ipv6_events"].open_perf_buffer(print_ipv6_events)
    main()
