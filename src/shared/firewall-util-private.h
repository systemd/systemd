/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "in-addr-util.h"
#include "sd-netlink.h"

enum FirewallBackend {
        FW_BACKEND_NONE,
#if HAVE_LIBIPTC
        FW_BACKEND_IPTABLES,
#endif
        FW_BACKEND_NFTABLES,
};

struct FirewallContext {
        enum FirewallBackend firewall_backend;
        sd_netlink *nfnl;
};

int fw_nftables_init(FirewallContext *ctx);
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
#endif
