/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "alloc-util.h"
#include "firewall-util.h"
#include "firewall-util-private.h"
#include "log.h"
#include "string-table.h"

static const char * const firewall_backend_table[_FW_BACKEND_MAX] = {
        [FW_BACKEND_NONE] = "none",
#if HAVE_LIBIPTC
        [FW_BACKEND_IPTABLES] = "iptables",
#endif
        [FW_BACKEND_NFTABLES] = "nftables",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(firewall_backend, FirewallBackend);

static void firewall_backend_probe(FirewallContext *ctx) {
        assert(ctx);

        if (ctx->backend != _FW_BACKEND_INVALID)
                return;

        if (fw_nftables_init(ctx) >= 0)
                ctx->backend = FW_BACKEND_NFTABLES;
        else
#if HAVE_LIBIPTC
                ctx->backend = FW_BACKEND_IPTABLES;
#else
                ctx->backend = FW_BACKEND_NONE;
#endif

        if (ctx->backend != FW_BACKEND_NONE)
                log_debug("Using %s as firewall backend.", firewall_backend_to_string(ctx->backend));
        else
                log_debug("No firewall backend found.");
}

int fw_ctx_new(FirewallContext **ret) {
        _cleanup_free_ FirewallContext *ctx = NULL;

        ctx = new(FirewallContext, 1);
        if (!ctx)
                return -ENOMEM;

        *ctx = (FirewallContext) {
                .backend = _FW_BACKEND_INVALID,
        };

        firewall_backend_probe(ctx);

        *ret = TAKE_PTR(ctx);
        return 0;
}

FirewallContext *fw_ctx_free(FirewallContext *ctx) {
        if (!ctx)
                return NULL;

        fw_nftables_exit(ctx);

        return mfree(ctx);
}

int fw_add_masquerade(
                FirewallContext **ctx,
                bool add,
                int af,
                const union in_addr_union *source,
                unsigned source_prefixlen) {

        int r;

        assert(ctx);

        if (!*ctx) {
                r = fw_ctx_new(ctx);
                if (r < 0)
                        return r;
        }

        switch ((*ctx)->backend) {
#if HAVE_LIBIPTC
        case FW_BACKEND_IPTABLES:
                return fw_iptables_add_masquerade(add, af, source, source_prefixlen);
#endif
        case FW_BACKEND_NFTABLES:
                return fw_nftables_add_masquerade(*ctx, add, af, source, source_prefixlen);
        default:
                return -EOPNOTSUPP;
        }
}

int fw_add_local_dnat(
                FirewallContext **ctx,
                bool add,
                int af,
                int protocol,
                uint16_t local_port,
                const union in_addr_union *remote,
                uint16_t remote_port,
                const union in_addr_union *previous_remote) {

        int r;

        assert(ctx);

        if (!*ctx) {
                r = fw_ctx_new(ctx);
                if (r < 0)
                        return r;
        }

        switch ((*ctx)->backend) {
#if HAVE_LIBIPTC
        case FW_BACKEND_IPTABLES:
                return fw_iptables_add_local_dnat(add, af, protocol, local_port, remote, remote_port, previous_remote);
#endif
        case FW_BACKEND_NFTABLES:
                return fw_nftables_add_local_dnat(*ctx, add, af, protocol, local_port, remote, remote_port, previous_remote);
        default:
                return -EOPNOTSUPP;
        }
}
