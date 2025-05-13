/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "firewall-util.h"
#include "firewall-util-private.h"
#include "log.h"
#include "netlink-util.h"
#include "string-table.h"
#include "string-util.h"

static const char * const firewall_backend_table[_FW_BACKEND_MAX] = {
        [FW_BACKEND_NONE] = "none",
#if HAVE_LIBIPTC
        [FW_BACKEND_IPTABLES] = "iptables",
#endif
        [FW_BACKEND_NFTABLES] = "nftables",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(firewall_backend, FirewallBackend);

static void firewall_backend_probe(FirewallContext *ctx, bool init_tables) {
        const char *e;

        assert(ctx);

        if (ctx->backend != _FW_BACKEND_INVALID)
                return;

        e = secure_getenv("SYSTEMD_FIREWALL_BACKEND");
        if (e) {
                if (streq(e, "nftables"))
                        ctx->backend = FW_BACKEND_NFTABLES;
                else if (streq(e, "iptables"))
#if HAVE_LIBIPTC
                        ctx->backend = FW_BACKEND_IPTABLES;
#else
                        log_debug("Unsupported firewall backend requested, ignoring: %s", e);
#endif
                else
                        log_debug("Unrecognized $SYSTEMD_FIREWALL_BACKEND value, ignoring: %s", e);
        }

        if (ctx->backend == _FW_BACKEND_INVALID) {

                if (fw_nftables_init_full(ctx, init_tables) >= 0)
                        ctx->backend = FW_BACKEND_NFTABLES;
                else
#if HAVE_LIBIPTC
                        ctx->backend = FW_BACKEND_IPTABLES;
#else
                        ctx->backend = FW_BACKEND_NONE;
#endif
        }

        if (ctx->backend != FW_BACKEND_NONE)
                log_debug("Using %s as firewall backend.", firewall_backend_to_string(ctx->backend));
        else
                log_debug("No firewall backend found.");
}

int fw_ctx_new_full(FirewallContext **ret, bool init_tables) {
        _cleanup_free_ FirewallContext *ctx = NULL;

        ctx = new(FirewallContext, 1);
        if (!ctx)
                return -ENOMEM;

        *ctx = (FirewallContext) {
                .backend = _FW_BACKEND_INVALID,
        };

        firewall_backend_probe(ctx, init_tables);

        *ret = TAKE_PTR(ctx);
        return 0;
}

int fw_ctx_new(FirewallContext **ret) {
        return fw_ctx_new_full(ret, /* init_tables= */ true);
}

FirewallContext *fw_ctx_free(FirewallContext *ctx) {
        if (!ctx)
                return NULL;

        fw_nftables_exit(ctx);

        return mfree(ctx);
}

size_t fw_ctx_get_reply_callback_count(FirewallContext *ctx) {
        if (!ctx || !ctx->nfnl)
                return 0;

        return netlink_get_reply_callback_count(ctx->nfnl);
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
