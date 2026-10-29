// Why not leave this out: go build refuses C sources in a package that does
// not use cgo, and this file is compiled by bpf2go, not by go build.
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2
#define AF_INET6 10
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define EEXIST 17
#define IP_FRAG_OFFSET 0x1fff
#define IPV4_IHL_MASK 0x0f
#define IPV4_IHL_WORD_LEN 4
#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16
#define IPV6_ADDR_WORDS 4
#define IPV4_LOOPBACK_NET 127
#define NETWORK_HEADER_OFF 0
#define V4_MAPPED_PREFIX_WORD 0x0000ffff
#define V4_MAPPED_ADDR_WORD 3
#define CGROUP_SKB_PASS 1
#define SOCKOPS_OK 1
#define FLOWS_PLACEHOLDER_ENTRIES 65536

enum hook {
	HOOK_INGRESS,
	HOOK_EGRESS,
};

/* Why not sort UDP the same way: TCP says who opened a connection and UDP
 * says nothing, so for UDP any direction here would be a guess. UDP records
 * keep both ports instead and leave the reading to whoever has the context. */
enum dir {
	DIR_NONE = 0,
	DIR_OUT = 1, /* this host called connect() */
	DIR_IN = 2,  /* this host accepted */
};

enum counter {
	CNT_DROPPED = 0,   /* bytes or connections that found the flow map full */
	CNT_UNTRACKED = 1, /* TCP packets on a socket established before attach */
	CNT_MAX,
};

/* Why not keep the ephemeral port of a TCP connection: it is new on every
 * connection, so keeping it makes a row per connection and the map grows with
 * the connection rate instead of with the number of peers. */
struct flow_key {
	__u8 family;
	__u8 proto;
	__u8 dir;
	__u8 pad;
	__u16 lport; /* 0 when it is the ephemeral side of a TCP connection */
	__u16 rport; /* likewise */
	__u8 laddr[IPV6_ADDR_LEN];
	__u8 raddr[IPV6_ADDR_LEN];
};

struct flow_val {
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u64 conns;
};

/* Why not one map: userspace would drain it while these programs write to it,
 * and a read could race a write to the same row. */
struct {
	/* Why not LRU: an LRU map makes room by evicting silently, and a total
	 * that may be missing rows without saying so is not worth adding up. */
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLOWS_PLACEHOLDER_ENTRIES);
	__type(key, struct flow_key);
	__type(value, struct flow_val);
} flows0 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLOWS_PLACEHOLDER_ENTRIES);
	__type(key, struct flow_key);
	__type(value, struct flow_val);
} flows1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} filling SEC(".maps");

/* Why not reset these after each read: a count landing between the read and
 * the reset would be lost. Userspace reports the difference instead. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CNT_MAX);
	__type(key, enum counter);
	__type(value, __u64);
} counters SEC(".maps");

/* Why socket storage rather than a hash keyed by socket: it is freed with the
 * socket, so it has no capacity to run out of and nothing to clean up. */
struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, enum dir);
} sk_dir SEC(".maps");

/* Why not the uapi iphdr: its version/ihl bitfields are laid out by the
 * headers of the build host, which is wrong for the big-endian object. */
struct ipv4 {
	__u8 vihl;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__be16 check;
	__u8 saddr[IPV4_ADDR_LEN];
	__u8 daddr[IPV4_ADDR_LEN];
};

struct l4_ports {
	__be16 src;
	__be16 dst;
};

struct ipv6 {
	__u8 vtcfl[4];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[IPV6_ADDR_LEN];
	__u8 daddr[IPV6_ADDR_LEN];
};

static __always_inline void count(enum counter i)
{
	__u64 *c = bpf_map_lookup_elem(&counters, &i);
	if (c)
		(*c)++;
}

/* Why not keep a row per connection, as conntrack does: such a table grows
 * with the connection rate and sits in the packet path when it fills up. This
 * one grows with the number of peers, and filling it up loses only a count. */
static __always_inline void add(void *flows, struct flow_key *k, struct flow_val *more)
{
	struct flow_val *v = bpf_map_lookup_elem(flows, k);
	if (!v) {
		struct flow_val zero = {};
		long err = bpf_map_update_elem(flows, k, &zero, BPF_NOEXIST);
		/* Why not count EEXIST as dropped: it is another CPU inserting
		 * the same row first. */
		if (err && err != -EEXIST) {
			count(CNT_DROPPED);
			return;
		}
		v = bpf_map_lookup_elem(flows, k);
		if (!v) {
			count(CNT_DROPPED);
			return;
		}
	}
	if (more->tx_bytes)
		__sync_fetch_and_add(&v->tx_bytes, more->tx_bytes);
	if (more->rx_bytes)
		__sync_fetch_and_add(&v->rx_bytes, more->rx_bytes);
	if (more->conns)
		__sync_fetch_and_add(&v->conns, more->conns);
}

/* Why not pick the map once and pass it to a single call: one helper call
 * site fed two different maps defeats the verifier's per-site map tracking.
 * The always_inline expands add() twice, one site per map. */
static __always_inline void account(struct flow_key *k, struct flow_val *more)
{
	__u32 zero = 0;
	__u32 *filling_idx = bpf_map_lookup_elem(&filling, &zero);
	if (filling_idx && *filling_idx == 1)
		add(&flows1, k, more);
	else
		add(&flows0, k, more);
}

static __always_inline int is_v6_loopback(const __u8 a[IPV6_ADDR_LEN])
{
#pragma unroll
	for (int i = 0; i < IPV6_ADDR_LEN - 1; i++)
		if (a[i])
			return 0;
	return a[IPV6_ADDR_LEN - 1] == 1;
}

/* Why not record loopback: it never enters or leaves the host. */
static __always_inline int is_loopback(struct flow_key *k)
{
	if (k->family == AF_INET)
		return k->raddr[0] == IPV4_LOOPBACK_NET;
	return is_v6_loopback(k->raddr);
}

static __always_inline int is_tcp_open_state(__u32 state)
{
	switch (state) {
	case BPF_TCP_ESTABLISHED:
	case BPF_TCP_FIN_WAIT1:
	case BPF_TCP_FIN_WAIT2:
	case BPF_TCP_CLOSE_WAIT:
	case BPF_TCP_CLOSING:
	case BPF_TCP_LAST_ACK:
		return 1;
	}
	return 0;
}

static __always_inline __u32 ipv4_header_len(const struct ipv4 *ip)
{
	return (ip->vihl & IPV4_IHL_MASK) * IPV4_IHL_WORD_LEN;
}

/* Why not take the addresses from skb->sk: an unconnected UDP socket has no
 * peer there, and the packet always has both. */
static __always_inline int parse(struct __sk_buff *skb, enum hook hook, struct flow_key *k)
{
	__u32 l4off;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct ipv4 ip;
		if (bpf_skb_load_bytes(skb, NETWORK_HEADER_OFF, &ip, sizeof(ip)))
			return -1;
		if (ip.frag_off & bpf_htons(IP_FRAG_OFFSET))
			return -1;
		k->family = AF_INET;
		k->proto = ip.protocol;
		l4off = ipv4_header_len(&ip);
		if (hook == HOOK_EGRESS) {
			__builtin_memcpy(k->laddr, ip.saddr, IPV4_ADDR_LEN);
			__builtin_memcpy(k->raddr, ip.daddr, IPV4_ADDR_LEN);
		} else {
			__builtin_memcpy(k->laddr, ip.daddr, IPV4_ADDR_LEN);
			__builtin_memcpy(k->raddr, ip.saddr, IPV4_ADDR_LEN);
		}
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6 ip6;
		if (bpf_skb_load_bytes(skb, NETWORK_HEADER_OFF, &ip6, sizeof(ip6)))
			return -1;
		k->family = AF_INET6;
		k->proto = ip6.nexthdr;
		l4off = sizeof(ip6);
		if (hook == HOOK_EGRESS) {
			__builtin_memcpy(k->laddr, ip6.saddr, IPV6_ADDR_LEN);
			__builtin_memcpy(k->raddr, ip6.daddr, IPV6_ADDR_LEN);
		} else {
			__builtin_memcpy(k->laddr, ip6.daddr, IPV6_ADDR_LEN);
			__builtin_memcpy(k->raddr, ip6.saddr, IPV6_ADDR_LEN);
		}
	} else {
		return -1;
	}

	if (k->proto != IPPROTO_TCP && k->proto != IPPROTO_UDP)
		return -1;

	struct l4_ports ports;
	if (bpf_skb_load_bytes(skb, l4off, &ports, sizeof(ports)))
		return -1;
	if (hook == HOOK_EGRESS) {
		k->lport = bpf_ntohs(ports.src);
		k->rport = bpf_ntohs(ports.dst);
	} else {
		k->lport = bpf_ntohs(ports.dst);
		k->rport = bpf_ntohs(ports.src);
	}
	return 0;
}

/* Why not read context fields directly: the verifier accepts only each
 * field's own width, and clang merges neighbouring elements into a u64 load
 * or splits a memcpy into bytes. */
#define CTX32(f) (*(volatile __u32 *)&(f))

static __always_inline int is_v4_mapped(const __u32 a[IPV6_ADDR_WORDS])
{
	return a[0] == 0 && a[1] == 0 && a[2] == bpf_htonl(V4_MAPPED_PREFIX_WORD);
}

static __always_inline void set_v4_addrs(struct flow_key *k, __u32 l, __u32 r)
{
	k->family = AF_INET;
	__builtin_memcpy(k->laddr, &l, IPV4_ADDR_LEN);
	__builtin_memcpy(k->raddr, &r, IPV4_ADDR_LEN);
}

static __always_inline void set_v6_addrs(struct flow_key *k, const __u32 l[IPV6_ADDR_WORDS],
					 const __u32 r[IPV6_ADDR_WORDS])
{
	/* Why not keep a v4-mapped address as inet6: the connection speaks IPv4
	 * on the wire, and its records should read like those of an IPv4
	 * socket. */
	if (is_v4_mapped(r)) {
		set_v4_addrs(k, l[V4_MAPPED_ADDR_WORD], r[V4_MAPPED_ADDR_WORD]);
		return;
	}
	k->family = AF_INET6;
	__builtin_memcpy(k->laddr, l, IPV6_ADDR_LEN);
	__builtin_memcpy(k->raddr, r, IPV6_ADDR_LEN);
}

/* Why not keep the addresses and ports from the packet: on egress they are
 * already past NAT, while sockops and ingress see the socket's own, so one
 * DNAT'd connection would split across two records. */
static __always_inline int set_addrs_from_socket(struct flow_key *k, struct bpf_sock *sk)
{
	if (sk->family == AF_INET) {
		set_v4_addrs(k, CTX32(sk->src_ip4), CTX32(sk->dst_ip4));
	} else if (sk->family == AF_INET6) {
		__u32 l[IPV6_ADDR_WORDS] = {CTX32(sk->src_ip6[0]), CTX32(sk->src_ip6[1]),
					    CTX32(sk->src_ip6[2]), CTX32(sk->src_ip6[3])};
		__u32 r[IPV6_ADDR_WORDS] = {CTX32(sk->dst_ip6[0]), CTX32(sk->dst_ip6[1]),
					    CTX32(sk->dst_ip6[2]), CTX32(sk->dst_ip6[3])};
		set_v6_addrs(k, l, r);
	} else {
		return -1;
	}
	/* Why not ntohs for both: src_port is in host order, dst_port in
	 * network order. */
	k->lport = sk->src_port;
	k->rport = bpf_ntohs(sk->dst_port);
	return 0;
}

static __always_inline int tcp_key_from_socket(struct __sk_buff *skb, struct flow_key *k)
{
	struct bpf_sock *sk = skb->sk;
	if (!sk)
		return -1;
	/* Why not count request and time-wait sockets: they carry only the
	 * handshake and teardown, which say nothing the full socket does not. */
	sk = bpf_sk_fullsock(sk);
	if (!sk)
		return -1;
	enum dir *dir = bpf_sk_storage_get(&sk_dir, sk, NULL, 0);
	if (!dir) {
		/* Why not count every socket without a direction: a listener or
		 * a connect in progress has none yet, and only an open one has
		 * lost it for good, by being established before attach. */
		if (is_tcp_open_state(sk->state))
			count(CNT_UNTRACKED);
		return -1;
	}
	k->dir = *dir;
	if (set_addrs_from_socket(k, sk))
		return -1;
	/* Why not rely on the check made on the packet: NAT can make the packet
	 * and the socket disagree, and sockops decides on the socket's. */
	if (is_loopback(k))
		return -1;
	/* Why not if/else assigning one field or the other: clang folds that
	 * into an OR on the stack pointer, which the verifier rejects.
	 * Selecting values keeps it to arithmetic on numbers. */
	k->lport = k->dir == DIR_OUT ? 0 : k->lport;
	k->rport = k->dir == DIR_OUT ? k->rport : 0;
	return 0;
}

/* Why not trace tcp_sendmsg/udp_sendmsg and their receive counterparts: those
 * are kernel functions with no promise of staying put. The cgroup attach
 * points are UAPI and see every packet a local socket sends or receives. */
static __always_inline void handle(struct __sk_buff *skb, enum hook hook)
{
	struct flow_key k;
	__builtin_memset(&k, 0, sizeof(k));

	if (parse(skb, hook, &k))
		return;
	if (is_loopback(&k))
		return;
	if (k.proto == IPPROTO_TCP && tcp_key_from_socket(skb, &k))
		return;

	struct flow_val more = {};
	if (hook == HOOK_EGRESS)
		more.tx_bytes = skb->len;
	else
		more.rx_bytes = skb->len;
	account(&k, &more);
}

/* Why not return a verdict: anything but CGROUP_SKB_PASS drops the packet,
 * and these only observe. */
SEC("cgroup_skb/egress")
int on_egress(struct __sk_buff *skb)
{
	handle(skb, HOOK_EGRESS);
	return CGROUP_SKB_PASS;
}

SEC("cgroup_skb/ingress")
int on_ingress(struct __sk_buff *skb)
{
	handle(skb, HOOK_INGRESS);
	return CGROUP_SKB_PASS;
}

/* Why not infer the direction from the packets: ACTIVE_ and
 * PASSIVE_ESTABLISHED are the kernel stating which side opened the
 * connection, called once per socket, with no flag to enable first. */
SEC("sockops")
int on_sockops(struct bpf_sock_ops *ops)
{
	enum dir dir;

	switch (ops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		dir = DIR_OUT;
		break;
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		dir = DIR_IN;
		break;
	default:
		return SOCKOPS_OK;
	}

	struct bpf_sock *sk = ops->sk;
	if (!sk)
		return SOCKOPS_OK;
	enum dir *d = bpf_sk_storage_get(&sk_dir, sk, NULL, BPF_SK_STORAGE_GET_F_CREATE);
	if (!d)
		return SOCKOPS_OK;
	*d = dir;

	struct flow_key k;
	__builtin_memset(&k, 0, sizeof(k));
	k.proto = IPPROTO_TCP;
	k.dir = dir;

	if (ops->family == AF_INET) {
		set_v4_addrs(&k, CTX32(ops->local_ip4), CTX32(ops->remote_ip4));
	} else if (ops->family == AF_INET6) {
		__u32 l[IPV6_ADDR_WORDS] = {CTX32(ops->local_ip6[0]), CTX32(ops->local_ip6[1]),
					    CTX32(ops->local_ip6[2]), CTX32(ops->local_ip6[3])};
		__u32 r[IPV6_ADDR_WORDS] = {CTX32(ops->remote_ip6[0]), CTX32(ops->remote_ip6[1]),
					    CTX32(ops->remote_ip6[2]), CTX32(ops->remote_ip6[3])};
		set_v6_addrs(&k, l, r);
	} else {
		return SOCKOPS_OK;
	}

	if (is_loopback(&k))
		return SOCKOPS_OK;

	/* Why not ntohs for both: remote_port is in network order in the upper
	 * half of a u32, while local_port is already in host order. */
	if (dir == DIR_OUT)
		k.rport = bpf_ntohl(ops->remote_port);
	else
		k.lport = ops->local_port;

	struct flow_val more = {.conns = 1};
	account(&k, &more);
	return SOCKOPS_OK;
}
