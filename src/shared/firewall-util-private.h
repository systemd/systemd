/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "sd-netlink.h"

#include "firewall-util.h"
#include "in-addr-util.h"

typedef enum FirewallBackend {
        FW_BACKEND_NONE,
#if HAVE_LIBIPTC
        FW_BACKEND_IPTABLES,
#endif
        FW_BACKEND_NFTABLES,
        _FW_BACKEND_MAX,
        _FW_BACKEND_INVALID = -EINVAL,
} FirewallBackend;

struct FirewallContext {
        FirewallBackend backend;
        sd_netlink *nfnl;
};

const char* firewall_backend_to_string(FirewallBackend b) _const_;

int fw_nftables_init(FirewallContext *ctx);
int fw_nftables_init_full(FirewallContext *ctx, bool init_tables);
void fw_nftables_exit(FirewallContext *ctx);

int fw_nftables_add_masquerade(
                FirewallContext *ctx,
                bool add,
                int af,
                const union in_addr_union *source,
                unsigned source_prefixlen);

int fw_nftables_add_local_dnat(
                FirewallContext *ctx,
                bool add,
                int af,
                int protocol,
                uint16_t local_port,
                const union in_addr_union *remote,
                uint16_t remote_port,
                const union in_addr_union *previous_remote);

#if HAVE_LIBIPTC
struct xtc_handle;

int fw_iptables_add_masquerade(
                bool add,
                int af,
                const union in_addr_union *source,
                unsigned source_prefixlen);

int fw_iptables_add_local_dnat(
                bool add,
                int af,
                int protocol,
                uint16_t local_port,
                const union in_addr_union *remote,
                uint16_t remote_port,
                const union in_addr_union *previous_remote);

int fw_iptables_init_nat(struct xtc_handle **ret);
#endif
