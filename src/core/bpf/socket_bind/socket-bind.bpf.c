/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

#include "socket-bind-api.bpf.h"
/* <linux/types.h> must precede <bpf/bpf_helpers.h> due to
 * <bpf/bpf_helpers.h> does not depend from type header by design.
 */
#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <netinet/in.h>
#include <stdbool.h>

/*
 * max_entries is set from user space with bpf_map__set_max_entries helper.
 */
struct socket_bind_map_t {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, struct socket_bind_rule);
};

enum socket_bind_action {
        SOCKET_BIND_DENY = 0,
        SOCKET_BIND_ALLOW = 1,
};

struct socket_bind_map_t sd_bind_allow SEC(".maps");
struct socket_bind_map_t sd_bind_deny SEC(".maps");

static __always_inline bool match_af(
                __u8 address_family, const struct socket_bind_rule *r) {
        return r->address_family == AF_UNSPEC || address_family == r->address_family;
}

static __always_inline bool match_protocol(
                __u32 protocol, const struct socket_bind_rule *r) {
        return r->protocol == 0 || r->protocol == protocol;
}

static __always_inline bool match_user_port(
                __u16 port, const struct socket_bind_rule *r) {
        return r->nr_ports == 0 ||
                (port >= r->port_min && port < r->port_min + (__u32) r->nr_ports);
}

static __always_inline bool match(
                __u8 address_family,
                __u32 protocol,
                __u16 port,
                const struct socket_bind_rule *r) {
        if (r->address_family == SOCKET_BIND_RULE_AF_MATCH_NOTHING)
                return false;

        return match_af(address_family, r) &&
                match_protocol(protocol, r) &&
                match_user_port(port, r);
}

static __always_inline bool match_rules(
                struct bpf_sock_addr *ctx,
                struct socket_bind_map_t *rules) {
        volatile __u32 user_port = ctx->user_port;
        __u16 port = (__u16)bpf_ntohs(user_port);

        for (__u32 i = 0; i < SOCKET_BIND_MAX_RULES; ++i) {
                const __u32 key = i;
                const struct socket_bind_rule *rule = bpf_map_lookup_elem(rules, &key);

                /* Lookup returns NULL if iterator is advanced past the last
                 * element put in the map. */
                if (!rule)
                        break;

                if (match(ctx->user_family, ctx->protocol, port, rule))
                        return true;
        }

        return false;
}

static __always_inline int bind_socket(struct bpf_sock_addr *ctx) {
        if (match_rules(ctx, &sd_bind_allow))
                return SOCKET_BIND_ALLOW;

        if (match_rules(ctx, &sd_bind_deny))
                return SOCKET_BIND_DENY;

        return SOCKET_BIND_ALLOW;
}

SEC("cgroup/bind4")
int sd_bind4(struct bpf_sock_addr *ctx) {
        if (ctx->user_family != AF_INET || ctx->family != AF_INET)
                return SOCKET_BIND_ALLOW;

        return bind_socket(ctx);
}

SEC("cgroup/bind6")
int sd_bind6(struct bpf_sock_addr *ctx) {
        if (ctx->user_family != AF_INET6 || ctx->family != AF_INET6)
                return SOCKET_BIND_ALLOW;

        return bind_socket(ctx);
}

char _license[] SEC("license") = "GPL";
