// BCC sensor: app-scoped connect/exec/accept, API-port inbound SYN, delivered
// API receive bytes and API->mock send bytes. Byte probes are published only
// after attachment and a full healthy window; their accuracy still needs
// independent VM checks.
#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>

#ifndef API_PID
#error "API_PID must identify the target API process"
#endif
#ifndef MOCK_PORT
#define MOCK_PORT 8001
#endif
#ifndef API_PORT
#define API_PORT 8000
#endif

struct ipv4_addr {
    unsigned short family;
    unsigned short port;
    unsigned int address;
    unsigned char padding[8];
};

struct pending_connect {
    unsigned int ip;
    unsigned short port;
};

struct egress_scope {
    unsigned int daddr;
    unsigned short dport;
};

struct kernel_event {
    unsigned long long ts_ns;
    unsigned int pid;
    unsigned int ip;
    unsigned short port;
    int result;
    unsigned char kind; // 1: connect; 2: exec; 3: accept; 4: SYN; 5: recv; 6: sent; 7: rejected SYN
    char comm[16];
};

BPF_HASH(pending, unsigned int, struct pending_connect);
BPF_HASH(egress_pending, unsigned int, struct egress_scope);
BPF_HASH(descendants, unsigned int, unsigned char);
BPF_PERF_OUTPUT(events);
// BPF perf output drops silently when a ring is full and does not produce a
// PERF_RECORD_LOST sample, so bookkeeping must follow the helper's return.
BPF_ARRAY(submit_dropped, u64, 1);

static __always_inline void emit(void *ctx, struct kernel_event *event) {
    unsigned int key = 0;
    if (events.perf_submit(ctx, event, sizeof(*event)) < 0) {
        u64 *dropped = submit_dropped.lookup(&key);
        if (dropped)
            lock_xadd(dropped, 1);
    }
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    unsigned long long id = bpf_get_current_pid_tgid();
    if ((id >> 32) != API_PID)
        return 0;
    struct ipv4_addr addr = {};
    if (bpf_probe_read_user(&addr, sizeof(addr), (void *)args->uservaddr) != 0)
        return 0;
    if (addr.family != 2) // AF_INET; never infer a peer from IPv6
        return 0;
    unsigned short port = __builtin_bswap16(addr.port);
    if (port != MOCK_PORT)
        return 0;
    unsigned int tid = (unsigned int)id;
    struct pending_connect item = {.ip = addr.address, .port = port};
    pending.update(&tid, &item);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_connect) {
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    struct pending_connect *item = pending.lookup(&tid);
    if (!item)
        return 0;
    struct kernel_event event = {};
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ip = item->ip;
    event.port = item->port;
    event.result = args->ret;
    event.kind = 1;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    emit(args, &event);
    pending.delete(&tid);
    return 0;
}

// This returns a completed accepted socket; it is NOT a SYN count.
// Filter both API process and the local listening port, rather than counting
// unrelated services or making a host-wide "conn_rate" claim.
int on_accept(struct pt_regs *ctx) {
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    if (tgid != API_PID)
        return 0;
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk)
        return 0;
    unsigned short family = 0, local_port = 0;
    unsigned int peer = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    bpf_probe_read_kernel(&local_port, sizeof(local_port), &sk->__sk_common.skc_num);
    if (family != 2 || local_port != API_PORT)
        return 0;
    bpf_probe_read_kernel(&peer, sizeof(peer), &sk->__sk_common.skc_daddr);
    struct kernel_event event = {};
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = tgid;
    event.ip = peer;
    event.port = local_port;
    event.kind = 3;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    emit(ctx, &event);
    return 0;
}

// Packet path, not a syscall or an accepted socket. Count incoming IPv4 SYN
// packets to the configured API port independently, including retransmissions.
// A packet may never reach ASGI. Do not use the current task's PID as API PID.
int on_syn(struct pt_regs *ctx, struct sk_buff *skb) {
    if (!skb)
        return 0;
    unsigned char *head = 0;
    unsigned short offset = 0;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&offset, sizeof(offset), &skb->network_header);
    if (!head || offset == 0xffff)
        return 0;
    struct iphdr iph = {};
    if (bpf_probe_read_kernel(&iph, sizeof(iph), head + offset) != 0)
        return 0;
    if (iph.version != 4 || iph.protocol != 6 || iph.ihl < 5)
        return 0;
    if ((__builtin_bswap16(iph.frag_off) & 0x1fff) != 0)
        return 0;
    struct tcphdr th = {};
    if (bpf_probe_read_kernel(&th, sizeof(th), head + offset + iph.ihl * 4) != 0)
        return 0;
    if (__builtin_bswap16(th.dest) != API_PORT || !th.syn || th.ack)
        return 0;
    struct kernel_event event = {};
    event.ts_ns = bpf_ktime_get_ns();
    event.ip = iph.saddr;
    event.port = API_PORT;
    event.kind = 4;
    emit(ctx, &event);
    return 0;
}

// A failed connection has one deliberately narrow meaning here: an inbound
// IPv4 SYN to API_PORT for which the local TCP stack sends a reset. This
// captures a kernel-observed local rejection (for example, no listener), not
// failed HTTP authentication, client abandonment or every timeout.
int on_failed_syn(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    if (!skb)
        return 0;
    unsigned char *head = 0;
    unsigned short offset = 0;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&offset, sizeof(offset), &skb->network_header);
    if (!head || offset == 0xffff)
        return 0;
    struct iphdr iph = {};
    if (bpf_probe_read_kernel(&iph, sizeof(iph), head + offset) != 0)
        return 0;
    if (iph.version != 4 || iph.protocol != 6 || iph.ihl < 5)
        return 0;
    if ((__builtin_bswap16(iph.frag_off) & 0x1fff) != 0)
        return 0;
    struct tcphdr th = {};
    if (bpf_probe_read_kernel(&th, sizeof(th), head + offset + iph.ihl * 4) != 0)
        return 0;
    if (__builtin_bswap16(th.dest) != API_PORT || !th.syn || th.ack)
        return 0;
    struct kernel_event event = {};
    event.ts_ns = bpf_ktime_get_ns();
    event.ip = iph.saddr;
    event.port = API_PORT;
    event.kind = 7;
    emit(ctx, &event);
    return 0;
}

// tcp_sendmsg returns actual bytes accepted by TCP for API->mock application
// data. This is not wire length and does not count kernel control segments.
// Only the API process and configured mock port are scoped.
int on_egress_enter(struct pt_regs *ctx, struct sock *sk) {
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    if (tgid != API_PID || !sk)
        return 0;
    unsigned short family = 0, dport = 0;
    unsigned int daddr = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    if (family != 2 || __builtin_bswap16(dport) != MOCK_PORT)
        return 0;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    struct egress_scope item = {.daddr = daddr, .dport = MOCK_PORT};
    egress_pending.update(&tid, &item);
    return 0;
}

int on_egress_return(struct pt_regs *ctx) {
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    if (tgid != API_PID)
        return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    struct egress_scope *item = egress_pending.lookup(&tid);
    if (!item)
        return 0;
    int sent = PT_REGS_RC(ctx);
    if (sent > 0) {
        struct kernel_event event = {};
        event.ts_ns = bpf_ktime_get_ns();
        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.ip = item->daddr;
        event.port = item->dport;
        event.result = sent;
        event.kind = 6;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        emit(ctx, &event);
    }
    egress_pending.delete(&tid);
    return 0;
}

// tcp_cleanup_rbuf reports bytes delivered to the receiving socket. This is
// not packet wire length and excludes retransmissions discarded by TCP.
// Scope by the actual API process, listening port and IPv4 accepted peer.
int on_inbound_bytes(struct pt_regs *ctx, struct sock *sk, int copied) {
    unsigned int tgid = bpf_get_current_pid_tgid() >> 32;
    if (tgid != API_PID || !sk || copied <= 0)
        return 0;
    unsigned short family = 0, local_port = 0;
    unsigned int peer = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    bpf_probe_read_kernel(&local_port, sizeof(local_port), &sk->__sk_common.skc_num);
    if (family != 2 || local_port != API_PORT)
        return 0;
    bpf_probe_read_kernel(&peer, sizeof(peer), &sk->__sk_common.skc_daddr);
    struct kernel_event event = {};
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = tgid;
    event.ip = peer;
    event.port = local_port;
    event.result = copied;
    event.kind = 5;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    emit(ctx, &event);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_fork) {
    unsigned int parent = bpf_get_current_pid_tgid() >> 32;
    unsigned char *tracked = descendants.lookup(&parent);
    if (parent != API_PID && !tracked)
        return 0;
    unsigned int child = args->child_pid;
    unsigned char one = 1;
    descendants.update(&child, &one);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exec) {
    unsigned int pid = args->pid;
    unsigned char *tracked = descendants.lookup(&pid);
    if (!tracked)
        return 0;
    struct kernel_event event = {};
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = pid;
    event.kind = 2;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    emit(args, &event);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    unsigned int pid = args->pid;
    descendants.delete(&pid);
    pending.delete(&pid);
    egress_pending.delete(&pid);
    return 0;
}
