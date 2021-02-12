/* SPDX-License-Identifier: GPL */

/* <linux/types.h> must precede <bpf/bpf_helpers.h> due to integer types
 * in bpf helpers signatures.
 */
#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <netinet/in.h>

/* Binding is allowed only to ports specified in ports_v{4|6} map.
 * Ports are in host order.
 * max_entries is set from user space by bpf_map__resize helper.
 */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, __u16);
        __type(value, __u8);
        __uint(max_entries, 0);
} ports_v6 SEC(".maps");

struct ports_v4 {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, __u16);
        __type(value, __u8);
        __uint(max_entries, 0);
} ports_v4 SEC(".maps");

static __always_inline int allow_bind_impl(
                struct bpf_sock_addr* ctx,
                void *ports) {
        __u16 port_key;
        __u8* port;

        volatile __u32 user_port = ctx->user_port;
        port_key = (__u16)bpf_ntohs(user_port);
        port = bpf_map_lookup_elem(ports, &port_key);
        if (!port)
                return 0;

        return 1;
}

SEC("cgroup/bind6")
int allow_bind_v6(struct bpf_sock_addr* ctx) {
        if (ctx->user_family != AF_INET6 || ctx->family != AF_INET6)
                return 1;

        return allow_bind_impl(ctx, &ports_v6);
}

SEC("cgroup/bind4")
int allow_bind_v4(struct bpf_sock_addr* ctx) {
        if (ctx->user_family != AF_INET || ctx->family != AF_INET)
                return 1;

        return allow_bind_impl(ctx, &ports_v4);
}

char _license[] SEC("license") = "GPL";
